// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title EthereumL1Bridge
 * @author Soul Protocol
 * @notice Bridge adapter for Ethereum mainnet (L1) interoperability
 * @dev Handles cross-chain proof relay and state synchronization between Soul and Ethereum L1
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    Ethereum L1 Bridge                           │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
 * │  │  Deposit    │  │  Withdraw   │  │  Proof      │             │
 * │  │  Manager    │  │  Manager    │  │  Relay      │             │
 * │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
 * │         │                │                │                     │
 * │  ┌──────▼────────────────▼────────────────▼──────┐             │
 * │  │              State Commitment Engine           │             │
 * │  └────────────────────────────────────────────────┘             │
 * │         │                                                       │
 * │  ┌──────▼──────────────────────────────────────────┐           │
 * │  │           L2/Rollup Canonical Bridges           │           │
 * │  │  Arbitrum | Optimism | zkSync | Base | Scroll   │           │
 * │  └─────────────────────────────────────────────────┘           │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * SECURITY PROPERTIES:
 * - Uses canonical L2 bridges for finality guarantees
 * - Implements optimistic fraud proof window
 * - Supports EIP-4844 blob data for cost efficiency
 * - Rate limiting and circuit breakers for attack mitigation
 */
contract EthereumL1Bridge is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Supported L2 rollup types
    enum RollupType {
        OPTIMISTIC, // Arbitrum, Optimism, Base
        ZK_ROLLUP, // zkSync Era, Scroll, Linea, Polygon zkEVM
        VALIDIUM // Data availability off-chain
    }

    /// @notice State commitment status
    enum CommitmentStatus {
        PENDING,
        CHALLENGED,
        FINALIZED,
        REJECTED
    }

    /// @notice L2 chain configuration
    struct L2Config {
        uint256 chainId;
        string name;
        RollupType rollupType;
        address canonicalBridge;
        address messenger;
        address stateCommitmentChain;
        uint256 challengePeriod; // For optimistic rollups
        uint256 confirmationBlocks;
        bool enabled;
        uint256 gasLimit;
        uint256 lastSyncedBlock;
    }

    /// @notice Cross-chain state commitment
    struct StateCommitment {
        bytes32 commitmentId;
        uint256 sourceChainId;
        bytes32 stateRoot;
        bytes32 proofRoot;
        uint256 blockNumber;
        uint256 timestamp;
        CommitmentStatus status;
        uint256 challengeDeadline;
        address submitter;
        bytes32 blobVersionedHash; // EIP-4844 support
    }

    /// @notice Deposit record for L1 -> L2 transfers
    struct Deposit {
        bytes32 depositId;
        address depositor;
        uint256 targetChainId;
        address token;
        uint256 amount;
        bytes32 commitment; // Soul commitment for privacy
        uint256 timestamp;
        bool claimed;
    }

    /// @notice Withdrawal record for L2 -> L1 transfers
    struct Withdrawal {
        bytes32 withdrawalId;
        address recipient;
        uint256 sourceChainId;
        address token;
        uint256 amount;
        bytes32 nullifier; // Soul nullifier to prevent double-spend
        bytes32[] proof; // Merkle proof from L2
        uint256 timestamp;
        bool finalized;
        bool claimed;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice L2 chain configurations
    mapping(uint256 => L2Config) public l2Configs;

    /// @notice Supported chain IDs
    uint256[] public supportedChainIds;

    /// @notice State commitments from L2 chains
    mapping(bytes32 => StateCommitment) public stateCommitments;

    /// @notice Chain ID -> latest state root
    mapping(uint256 => bytes32) public latestStateRoots;

    /// @notice Deposits by ID
    mapping(bytes32 => Deposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => Withdrawal) public withdrawals;

    /// @notice Used nullifiers (cross-chain double-spend prevention)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Relayed proof hashes
    mapping(bytes32 => bool) public relayedProofs;

    /// @notice Ethereum mainnet chain ID (immutable)
    uint256 public constant ETHEREUM_CHAIN_ID = 1;

    /// @notice Challenge period for optimistic commitments (default: 7 days)
    uint256 public constant DEFAULT_CHALLENGE_PERIOD = 7 days;

    /// @notice Minimum bond for state commitment submission
    uint256 public minSubmissionBond = 0.1 ether;

    /// @notice Minimum bond required to challenge a commitment
    uint256 public minChallengeBond = 0.05 ether;

    /// @notice Actual bond deposited per commitment (commitmentId => bond)
    mapping(bytes32 => uint256) public commitmentBonds;

    /// @notice Challenge details (commitmentId => challenger)
    mapping(bytes32 => address) public challengeChallenger;

    /// @notice Challenge bonds (commitmentId => bond amount)
    mapping(bytes32 => uint256) public challengeBonds;

    /// @notice Rate limiting: max commitments per hour
    uint256 public maxCommitmentsPerHour = 100;
    uint256 public hourlyCommitmentCount;
    uint256 public lastHourReset;

    /// @notice Total deposits count
    uint256 public totalDeposits;

    /// @notice Total withdrawals count
    uint256 public totalWithdrawals;

    /// @notice Total state commitments
    uint256 public totalCommitments;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event L2ChainConfigured(
        uint256 indexed chainId,
        string name,
        RollupType rollupType,
        address canonicalBridge
    );

    event L2ChainUpdated(uint256 indexed chainId, bool enabled);

    event StateCommitmentSubmitted(
        bytes32 indexed commitmentId,
        uint256 indexed sourceChainId,
        bytes32 stateRoot,
        address submitter,
        bytes32 blobVersionedHash
    );

    event StateCommitmentChallenged(
        bytes32 indexed commitmentId,
        address challenger,
        bytes32 reason
    );

    event StateCommitmentFinalized(
        bytes32 indexed commitmentId,
        bytes32 stateRoot
    );

    event StateCommitmentRejected(
        bytes32 indexed commitmentId,
        address challenger
    );

    event ChallengeResolved(
        bytes32 indexed commitmentId,
        bool rejected,
        address bondRecipient
    );

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed depositor,
        uint256 indexed targetChainId,
        address token,
        uint256 amount,
        bytes32 commitment
    );

    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed recipient,
        uint256 indexed sourceChainId,
        uint256 amount
    );

    event WithdrawalFinalized(
        bytes32 indexed withdrawalId,
        address recipient,
        uint256 amount
    );

    event ProofRelayed(
        bytes32 indexed proofHash,
        uint256 indexed sourceChainId,
        bytes32 stateRoot
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ChainNotSupported(uint256 chainId);
    error ChainAlreadyConfigured(uint256 chainId);
    error ChainNotEnabled(uint256 chainId);
    error InvalidCommitment(bytes32 commitmentId);
    error CommitmentAlreadyExists(bytes32 commitmentId);
    error CommitmentNotPending(bytes32 commitmentId);
    error ChallengePeriodNotOver(bytes32 commitmentId, uint256 deadline);
    error ChallengePeriodOver(bytes32 commitmentId);
    error InsufficientBond(uint256 provided, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error DepositNotFound(bytes32 depositId);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error WithdrawalNotFinalized(bytes32 withdrawalId);
    error AlreadyClaimed();
    error RateLimitExceeded();
    error InvalidBlobIndex();
    error ZeroAddress();
    error ZeroAmount();
    error TransferFailed();
    error CommitmentNotChallenged(bytes32 commitmentId);
    error InsufficientChallengeBond(uint256 provided, uint256 required);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        lastHourReset = block.timestamp;

        // Initialize supported L2 chains
        _initializeL2Chains();
    }

    /*//////////////////////////////////////////////////////////////
                         L2 CHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize default L2 chain configurations
     */
    function _initializeL2Chains() internal {
        // Arbitrum One
        _configureL2Chain(
            L2Config({
                chainId: 42161,
                name: "Arbitrum One",
                rollupType: RollupType.OPTIMISTIC,
                canonicalBridge: address(0), // Set during deployment
                messenger: address(0),
                stateCommitmentChain: address(0),
                challengePeriod: 7 days,
                confirmationBlocks: 1,
                enabled: true,
                gasLimit: 1000000,
                lastSyncedBlock: 0
            })
        );

        // Optimism
        _configureL2Chain(
            L2Config({
                chainId: 10,
                name: "Optimism",
                rollupType: RollupType.OPTIMISTIC,
                canonicalBridge: address(0),
                messenger: address(0),
                stateCommitmentChain: address(0),
                challengePeriod: 7 days,
                confirmationBlocks: 1,
                enabled: true,
                gasLimit: 1000000,
                lastSyncedBlock: 0
            })
        );

        // Base
        _configureL2Chain(
            L2Config({
                chainId: 8453,
                name: "Base",
                rollupType: RollupType.OPTIMISTIC,
                canonicalBridge: address(0),
                messenger: address(0),
                stateCommitmentChain: address(0),
                challengePeriod: 7 days,
                confirmationBlocks: 1,
                enabled: true,
                gasLimit: 1000000,
                lastSyncedBlock: 0
            })
        );

        // zkSync Era
        _configureL2Chain(
            L2Config({
                chainId: 324,
                name: "zkSync Era",
                rollupType: RollupType.ZK_ROLLUP,
                canonicalBridge: address(0),
                messenger: address(0),
                stateCommitmentChain: address(0),
                challengePeriod: 0, // ZK rollups have instant finality
                confirmationBlocks: 1,
                enabled: true,
                gasLimit: 2000000,
                lastSyncedBlock: 0
            })
        );

        // Scroll
        _configureL2Chain(
            L2Config({
                chainId: 534352,
                name: "Scroll",
                rollupType: RollupType.ZK_ROLLUP,
                canonicalBridge: address(0),
                messenger: address(0),
                stateCommitmentChain: address(0),
                challengePeriod: 0,
                confirmationBlocks: 1,
                enabled: true,
                gasLimit: 1500000,
                lastSyncedBlock: 0
            })
        );

        // Linea
        _configureL2Chain(
            L2Config({
                chainId: 59144,
                name: "Linea",
                rollupType: RollupType.ZK_ROLLUP,
                canonicalBridge: address(0),
                messenger: address(0),
                stateCommitmentChain: address(0),
                challengePeriod: 0,
                confirmationBlocks: 1,
                enabled: true,
                gasLimit: 1000000,
                lastSyncedBlock: 0
            })
        );

        // Polygon zkEVM
        _configureL2Chain(
            L2Config({
                chainId: 1101,
                name: "Polygon zkEVM",
                rollupType: RollupType.ZK_ROLLUP,
                canonicalBridge: address(0),
                messenger: address(0),
                stateCommitmentChain: address(0),
                challengePeriod: 0,
                confirmationBlocks: 1,
                enabled: true,
                gasLimit: 1000000,
                lastSyncedBlock: 0
            })
        );
    }

    /**
     * @notice Configure an L2 chain
     */
    function _configureL2Chain(L2Config memory config) internal {
        l2Configs[config.chainId] = config;
        supportedChainIds.push(config.chainId);

        emit L2ChainConfigured(
            config.chainId,
            config.name,
            config.rollupType,
            config.canonicalBridge
        );
    }

    /**
     * @notice Add or update L2 chain configuration
     * @param config The chain configuration
     */
    function configureL2Chain(
        L2Config calldata config
    ) external onlyRole(OPERATOR_ROLE) {
        if (l2Configs[config.chainId].chainId == 0) {
            supportedChainIds.push(config.chainId);
        }

        l2Configs[config.chainId] = config;

        emit L2ChainConfigured(
            config.chainId,
            config.name,
            config.rollupType,
            config.canonicalBridge
        );
    }

    /**
     * @notice Set canonical bridge address for an L2
     * @param chainId The L2 chain ID
     * @param bridge The canonical bridge address
     */
    function setCanonicalBridge(
        uint256 chainId,
        address bridge
    ) external onlyRole(OPERATOR_ROLE) {
        if (l2Configs[chainId].chainId == 0) revert ChainNotSupported(chainId);
        if (bridge == address(0)) revert ZeroAddress();

        l2Configs[chainId].canonicalBridge = bridge;
    }

    /**
     * @notice Enable or disable an L2 chain
     * @param chainId The chain ID
     * @param enabled Whether to enable the chain
     */
    function setChainEnabled(
        uint256 chainId,
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        if (l2Configs[chainId].chainId == 0) revert ChainNotSupported(chainId);

        l2Configs[chainId].enabled = enabled;
        emit L2ChainUpdated(chainId, enabled);
    }

    /*//////////////////////////////////////////////////////////////
                      STATE COMMITMENT RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a state commitment from an L2 chain
     * @param sourceChainId The source L2 chain ID
     * @param stateRoot The state root from L2
     * @param proofRoot The Soul proof merkle root
     * @param blockNumber The L2 block number
     */
    function submitStateCommitment(
        uint256 sourceChainId,
        bytes32 stateRoot,
        bytes32 proofRoot,
        uint256 blockNumber
    ) external payable {
        _submitStateCommitment(
            sourceChainId,
            stateRoot,
            proofRoot,
            blockNumber,
            bytes32(0)
        );
    }

    /**
     * @notice Submit state commitment using EIP-4844 blob
     * @param sourceChainId The source L2 chain ID
     * @param stateRoot The state root from L2
     * @param proofRoot The Soul proof merkle root
     * @param blockNumber The L2 block number
     * @param blobIndex The index of the blob in the current transaction
     */
    function submitStateCommitmentWithBlob(
        uint256 sourceChainId,
        bytes32 stateRoot,
        bytes32 proofRoot,
        uint256 blockNumber,
        uint256 blobIndex
    ) external payable {
        bytes32 blobVersionedHash = _getBlobHash(blobIndex);
        if (blobVersionedHash == bytes32(0)) revert InvalidBlobIndex();
        _submitStateCommitment(
            sourceChainId,
            stateRoot,
            proofRoot,
            blockNumber,
            blobVersionedHash
        );
    }

    /**
     * @notice Get blob hash from the current transaction
     * @dev Uses EIP-4844 BLOBHASH opcode. Returns bytes32(0) if no blob at index.
     * @param index The blob index in the transaction
     * @return hash The versioned blob hash
     */
    function _getBlobHash(
        uint256 index
    ) internal view virtual returns (bytes32 hash) {
        // Use assembly to call BLOBHASH opcode (0x49)
        // This is EIP-4844 compliant and will return 0 if no blob at index
        assembly {
            hash := blobhash(index)
        }
    }

    /**
     * @notice Internal function to handle state commitment submission
     */
    function _submitStateCommitment(
        uint256 sourceChainId,
        bytes32 stateRoot,
        bytes32 proofRoot,
        uint256 blockNumber,
        bytes32 blobVersionedHash
    ) internal nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        L2Config storage config = l2Configs[sourceChainId];
        if (config.chainId == 0) revert ChainNotSupported(sourceChainId);
        if (!config.enabled) revert ChainNotEnabled(sourceChainId);
        if (msg.value < minSubmissionBond)
            revert InsufficientBond(msg.value, minSubmissionBond);

        // Rate limiting
        _checkRateLimit();

        bytes32 commitmentId = keccak256(
            abi.encodePacked(
                sourceChainId,
                stateRoot,
                proofRoot,
                blockNumber,
                block.timestamp,
                blobVersionedHash
            )
        );

        if (stateCommitments[commitmentId].commitmentId != bytes32(0)) {
            revert CommitmentAlreadyExists(commitmentId);
        }

        // Store the actual bond amount for accurate return later
        commitmentBonds[commitmentId] = msg.value;

        uint256 challengeDeadline = config.rollupType == RollupType.ZK_ROLLUP
            ? block.timestamp // ZK rollups finalize immediately
            : block.timestamp + config.challengePeriod;

        stateCommitments[commitmentId] = StateCommitment({
            commitmentId: commitmentId,
            sourceChainId: sourceChainId,
            stateRoot: stateRoot,
            proofRoot: proofRoot,
            blockNumber: blockNumber,
            timestamp: block.timestamp,
            status: config.rollupType == RollupType.ZK_ROLLUP
                ? CommitmentStatus.FINALIZED
                : CommitmentStatus.PENDING,
            challengeDeadline: challengeDeadline,
            submitter: msg.sender,
            blobVersionedHash: blobVersionedHash
        });

        // ZK rollups finalize immediately
        if (config.rollupType == RollupType.ZK_ROLLUP) {
            latestStateRoots[sourceChainId] = stateRoot;
            config.lastSyncedBlock = blockNumber;
        }

        totalCommitments++;
        hourlyCommitmentCount++;

        emit StateCommitmentSubmitted(
            commitmentId,
            sourceChainId,
            stateRoot,
            msg.sender,
            blobVersionedHash
        );
    }

    /**
     * @notice Challenge a pending state commitment (optimistic rollups only)
     * @param commitmentId The commitment to challenge
     * @param reason Challenge reason hash
     */
    function challengeCommitment(
        bytes32 commitmentId,
        bytes32 reason
    ) external payable nonReentrant {
        if (msg.value < minChallengeBond)
            revert InsufficientChallengeBond(msg.value, minChallengeBond);

        StateCommitment storage commitment = stateCommitments[commitmentId];

        if (commitment.commitmentId == bytes32(0))
            revert InvalidCommitment(commitmentId);
        if (commitment.status != CommitmentStatus.PENDING)
            revert CommitmentNotPending(commitmentId);
        if (block.timestamp >= commitment.challengeDeadline) {
            revert ChallengePeriodOver(commitmentId);
        }

        commitment.status = CommitmentStatus.CHALLENGED;
        challengeChallenger[commitmentId] = msg.sender;
        challengeBonds[commitmentId] = msg.value;

        emit StateCommitmentChallenged(commitmentId, msg.sender, reason);
    }

    /**
     * @notice Finalize a state commitment after challenge period
     * @param commitmentId The commitment to finalize
     */
    function finalizeCommitment(bytes32 commitmentId) external nonReentrant {
        StateCommitment storage commitment = stateCommitments[commitmentId];

        if (commitment.commitmentId == bytes32(0))
            revert InvalidCommitment(commitmentId);
        if (commitment.status != CommitmentStatus.PENDING)
            revert CommitmentNotPending(commitmentId);
        if (block.timestamp < commitment.challengeDeadline) {
            revert ChallengePeriodNotOver(
                commitmentId,
                commitment.challengeDeadline
            );
        }

        commitment.status = CommitmentStatus.FINALIZED;
        latestStateRoots[commitment.sourceChainId] = commitment.stateRoot;
        l2Configs[commitment.sourceChainId].lastSyncedBlock = commitment
            .blockNumber;

        // Return stored bond to submitter (not current minSubmissionBond which may drift)
        uint256 bondAmount = commitmentBonds[commitmentId];
        delete commitmentBonds[commitmentId];

        (bool success, ) = payable(commitment.submitter).call{
            value: bondAmount
        }("");
        if (!success) revert TransferFailed();

        emit StateCommitmentFinalized(commitmentId, commitment.stateRoot);
    }

    /**
     * @notice Resolve a challenged commitment (GUARDIAN or OPERATOR only)
     * @param commitmentId The challenged commitment
     * @param reject True if the commitment is invalid (challenger wins), false if valid (submitter wins)
     */
    function resolveChallenge(
        bytes32 commitmentId,
        bool reject
    ) external nonReentrant onlyRole(GUARDIAN_ROLE) {
        StateCommitment storage commitment = stateCommitments[commitmentId];

        if (commitment.commitmentId == bytes32(0))
            revert InvalidCommitment(commitmentId);
        if (commitment.status != CommitmentStatus.CHALLENGED)
            revert CommitmentNotChallenged(commitmentId);

        uint256 submitterBond = commitmentBonds[commitmentId];
        uint256 challengerBond = challengeBonds[commitmentId];
        address challenger = challengeChallenger[commitmentId];

        // Clean up storage
        delete commitmentBonds[commitmentId];
        delete challengeBonds[commitmentId];
        delete challengeChallenger[commitmentId];

        if (reject) {
            // Challenger wins: commitment is invalid
            commitment.status = CommitmentStatus.REJECTED;

            // Challenger gets their bond back + submitter's bond as reward
            uint256 totalReward = challengerBond + submitterBond;
            (bool success, ) = payable(challenger).call{value: totalReward}("");
            if (!success) revert TransferFailed();

            emit StateCommitmentRejected(commitmentId, challenger);
            emit ChallengeResolved(commitmentId, true, challenger);
        } else {
            // Submitter wins: commitment is valid, resume to PENDING for finalization
            commitment.status = CommitmentStatus.PENDING;
            commitmentBonds[commitmentId] = submitterBond;

            // Submitter gets challenger's bond as reward
            uint256 totalReward = challengerBond;
            (bool success, ) = payable(commitment.submitter).call{
                value: totalReward
            }("");
            if (!success) revert TransferFailed();

            emit ChallengeResolved(commitmentId, false, commitment.submitter);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT (L1 -> L2)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a deposit from L1 to L2 with privacy commitment
     * @param targetChainId The target L2 chain ID
     * @param commitment The Soul commitment for the deposit
     */
    function depositETH(
        uint256 targetChainId,
        bytes32 commitment
    ) external payable nonReentrant whenNotPaused {
        if (msg.value == 0) revert ZeroAmount();
        if (l2Configs[targetChainId].chainId == 0)
            revert ChainNotSupported(targetChainId);
        if (!l2Configs[targetChainId].enabled)
            revert ChainNotEnabled(targetChainId);
        if (commitment == bytes32(0)) revert InvalidCommitment(commitment);

        bytes32 depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                targetChainId,
                msg.value,
                commitment,
                block.timestamp,
                totalDeposits
            )
        );

        deposits[depositId] = Deposit({
            depositId: depositId,
            depositor: msg.sender,
            targetChainId: targetChainId,
            token: address(0), // ETH
            amount: msg.value,
            commitment: commitment,
            timestamp: block.timestamp,
            claimed: false
        });

        totalDeposits++;

        emit DepositInitiated(
            depositId,
            msg.sender,
            targetChainId,
            address(0),
            msg.value,
            commitment
        );

        // In production: call canonical bridge to relay deposit
        // L2Config storage config = l2Configs[targetChainId];
        // ICanonicalBridge(config.canonicalBridge).depositETH{value: msg.value}(...);
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL (L2 -> L1)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate withdrawal claim from L2
     * @param sourceChainId The source L2 chain ID
     * @param amount The withdrawal amount
     * @param nullifier The Soul nullifier to prevent double-spend
     * @param proof Merkle proof from L2 state
     */
    function initiateWithdrawal(
        uint256 sourceChainId,
        uint256 amount,
        bytes32 nullifier,
        bytes32[] calldata proof
    ) external nonReentrant whenNotPaused {
        if (l2Configs[sourceChainId].chainId == 0)
            revert ChainNotSupported(sourceChainId);
        if (!l2Configs[sourceChainId].enabled)
            revert ChainNotEnabled(sourceChainId);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        if (amount == 0) revert ZeroAmount();

        // Verify proof against latest state root
        bytes32 stateRoot = latestStateRoots[sourceChainId];
        if (!_verifyWithdrawalProof(stateRoot, nullifier, amount, proof)) {
            revert InvalidProof();
        }

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                msg.sender,
                sourceChainId,
                amount,
                nullifier,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = Withdrawal({
            withdrawalId: withdrawalId,
            recipient: msg.sender,
            sourceChainId: sourceChainId,
            token: address(0),
            amount: amount,
            nullifier: nullifier,
            proof: proof,
            timestamp: block.timestamp,
            finalized: l2Configs[sourceChainId].rollupType ==
                RollupType.ZK_ROLLUP,
            claimed: false
        });

        usedNullifiers[nullifier] = true;
        totalWithdrawals++;

        emit WithdrawalInitiated(
            withdrawalId,
            msg.sender,
            sourceChainId,
            amount
        );
    }

    /**
     * @notice Finalize a withdrawal after challenge period (optimistic rollups)
     * @param withdrawalId The withdrawal to finalize
     */
    function finalizeWithdrawal(bytes32 withdrawalId) external nonReentrant {
        Withdrawal storage withdrawal = withdrawals[withdrawalId];

        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.claimed) revert AlreadyClaimed();

        L2Config storage config = l2Configs[withdrawal.sourceChainId];

        // For optimistic rollups, check challenge period
        if (config.rollupType == RollupType.OPTIMISTIC) {
            if (
                block.timestamp < withdrawal.timestamp + config.challengePeriod
            ) {
                revert WithdrawalNotFinalized(withdrawalId);
            }
        }

        withdrawal.finalized = true;
    }

    /**
     * @notice Claim a finalized withdrawal
     * @param withdrawalId The withdrawal to claim
     */
    function claimWithdrawal(bytes32 withdrawalId) external nonReentrant {
        Withdrawal storage withdrawal = withdrawals[withdrawalId];

        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (!withdrawal.finalized) revert WithdrawalNotFinalized(withdrawalId);
        if (withdrawal.claimed) revert AlreadyClaimed();

        withdrawal.claimed = true;

        (bool success, ) = payable(withdrawal.recipient).call{
            value: withdrawal.amount
        }("");
        if (!success) revert TransferFailed();

        emit WithdrawalFinalized(
            withdrawalId,
            withdrawal.recipient,
            withdrawal.amount
        );
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Relay a Soul proof from L2 to L1
     * @param sourceChainId The source L2 chain
     * @param proofHash The proof hash
     * @param stateRoot The state root the proof is against
     */
    function relayProof(
        uint256 sourceChainId,
        bytes32 proofHash,
        bytes32 stateRoot,
        bytes calldata /* proofData */
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (l2Configs[sourceChainId].chainId == 0)
            revert ChainNotSupported(sourceChainId);
        if (relayedProofs[proofHash]) revert InvalidProof();

        // Verify the state root is valid
        if (latestStateRoots[sourceChainId] != stateRoot) {
            revert InvalidProof();
        }

        relayedProofs[proofHash] = true;

        emit ProofRelayed(proofHash, sourceChainId, stateRoot);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check rate limit
     */
    function _checkRateLimit() internal {
        if (block.timestamp >= lastHourReset + 1 hours) {
            hourlyCommitmentCount = 0;
            lastHourReset = block.timestamp;
        }

        if (hourlyCommitmentCount >= maxCommitmentsPerHour) {
            revert RateLimitExceeded();
        }
    }

    /**
     * @notice Verify withdrawal proof using Merkle tree verification
     * @param stateRoot The committed state root to verify against
     * @param nullifier The nullifier being spent
     * @param amount The withdrawal amount
     * @param proof The Merkle proof path
     * @return True if the proof is valid
     */
    function _verifyWithdrawalProof(
        bytes32 stateRoot,
        bytes32 nullifier,
        uint256 amount,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        // Validate inputs
        if (stateRoot == bytes32(0)) return false;
        if (proof.length == 0) return false;

        // Compute leaf hash
        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));

        // Verify Merkle proof
        bytes32 computedRoot = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedRoot <= proofElement) {
                computedRoot = keccak256(
                    abi.encodePacked(computedRoot, proofElement)
                );
            } else {
                computedRoot = keccak256(
                    abi.encodePacked(proofElement, computedRoot)
                );
            }
        }

        return computedRoot == stateRoot;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get supported chain IDs
     * @return Array of all registered L2 chain IDs
     */
    function getSupportedChainIds() external view returns (uint256[] memory) {
        return supportedChainIds;
    }

    /**
     * @notice Get L2 chain configuration
     * @param chainId The L2 chain ID to query
     * @return The L2Config struct for the given chain
     */
    function getL2Config(
        uint256 chainId
    ) external view returns (L2Config memory) {
        return l2Configs[chainId];
    }

    /**
     * @notice Check if a chain is supported
     * @param chainId The chain ID to check
     * @return True if the chain is configured and enabled
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return l2Configs[chainId].chainId != 0 && l2Configs[chainId].enabled;
    }

    /**
     * @notice Get latest state root for a chain
     * @param chainId The L2 chain ID
     * @return The most recently submitted state root
     */
    function getLatestStateRoot(
        uint256 chainId
    ) external view returns (bytes32) {
        return latestStateRoots[chainId];
    }

    /**
     * @notice Check if a nullifier has been used
     * @param nullifier The nullifier hash to check
     * @return True if the nullifier has already been spent
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set rate limit parameters
     * @param _maxCommitmentsPerHour The maximum number of commitments allowed per hour
     */
    function setRateLimits(
        uint256 _maxCommitmentsPerHour
    ) external onlyRole(OPERATOR_ROLE) {
        maxCommitmentsPerHour = _maxCommitmentsPerHour;
    }

    /**
     * @notice Set minimum submission bond
     * @param _minBond The minimum bond amount submitters must deposit
     */
    function setMinSubmissionBond(
        uint256 _minBond
    ) external onlyRole(OPERATOR_ROLE) {
        minSubmissionBond = _minBond;
    }

    /**
     * @notice Set maximum commitments per hour
     * @param _maxCommitments The new hourly commitment cap
     */
    function setMaxCommitmentsPerHour(
        uint256 _maxCommitments
    ) external onlyRole(OPERATOR_ROLE) {
        maxCommitmentsPerHour = _maxCommitments;
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
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH for deposits
     */
    receive() external payable {}
}
