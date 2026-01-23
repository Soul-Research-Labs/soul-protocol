// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "../sui/SuiPrimitives.sol";

/**
 * @title SuiBridgeAdapter
 * @notice Bridge adapter for Sui blockchain integration with PIL
 * @dev Implements:
 *      - Validator committee management (BLS signatures)
 *      - Checkpoint-based finality
 *      - Object-based transfers
 *      - Cross-domain nullifier binding
 *      - Rate limiting and circuit breaker
 */
contract SuiBridgeAdapter is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SuiPrimitives for *;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant BRIDGE_ADMIN_ROLE = keccak256("BRIDGE_ADMIN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant VALIDATOR_MANAGER_ROLE =
        keccak256("VALIDATOR_MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    uint256 private constant MAX_DAILY_VOLUME = 1_000_000 ether;
    uint256 private constant MAX_TRANSFER = 100_000 ether;
    uint256 private constant MIN_CONFIRMATIONS = 10;
    uint256 private constant MAX_RELAYER_FEE_BPS = 500; // 5%
    uint256 private constant CHECKPOINT_HISTORY_SIZE = 100;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Current Sui epoch
    uint64 public currentEpoch;

    /// @notice Current validator committee
    SuiPrimitives.ValidatorCommittee public currentCommittee;

    /// @notice Validator info mapping
    mapping(bytes32 => SuiPrimitives.ValidatorInfo) public validators;

    /// @notice Active validator addresses
    bytes32[] public activeValidators;

    /// @notice Checkpoint history (sequenceNumber => digest)
    mapping(uint64 => bytes32) public checkpointDigests;

    /// @notice Latest checkpoint sequence number
    uint64 public latestCheckpoint;

    /// @notice Processed checkpoints
    mapping(bytes32 => bool) public processedCheckpoints;

    /// @notice Consumed nullifiers
    mapping(bytes32 => bool) public consumedNullifiers;

    /// @notice PIL nullifier bindings (suiNullifier => pilNullifier)
    mapping(bytes32 => bytes32) public nullifierBindings;

    /// @notice Pending deposits (EVM -> Sui)
    mapping(bytes32 => DepositInfo) public pendingDeposits;

    /// @notice Completed withdrawals (Sui -> EVM)
    mapping(bytes32 => WithdrawalInfo) public completedWithdrawals;

    /// @notice Daily volume tracking
    mapping(uint256 => uint256) public dailyVolume;

    /// @notice User daily limits
    mapping(address => mapping(uint256 => uint256)) public userDailyVolume;
    mapping(address => uint256) public userDailyLimit;

    /// @notice Supported token mappings (Sui coin type => EVM token)
    mapping(bytes32 => address) public tokenMappings;

    /// @notice Reverse token mappings (EVM token => Sui coin type)
    mapping(address => bytes32) public reverseTokenMappings;

    /// @notice Relayer registry
    mapping(address => RelayerInfo) public relayers;

    /// @notice Circuit breaker state
    CircuitBreakerState public circuitBreaker;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct DepositInfo {
        address sender;
        address token;
        uint256 amount;
        bytes32 suiRecipient;
        uint64 timestamp;
        bool claimed;
        bool refunded;
    }

    struct WithdrawalInfo {
        bytes32 suiSender;
        address recipient;
        address token;
        uint256 amount;
        bytes32 txDigest;
        uint64 epoch;
        uint64 timestamp;
        bytes32 nullifier;
    }

    struct RelayerInfo {
        bool isActive;
        uint256 feeBps;
        uint256 totalRelayed;
        uint256 lastActive;
    }

    struct CircuitBreakerState {
        bool triggered;
        uint256 triggeredAt;
        uint256 cooldownPeriod;
        uint256 anomalyCount;
        uint256 lastAnomalyAt;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        bytes32 indexed suiRecipient,
        address token,
        uint256 amount
    );

    event DepositClaimed(bytes32 indexed depositId, bytes32 suiTxDigest);

    event DepositRefunded(
        bytes32 indexed depositId,
        address sender,
        uint256 amount
    );

    event WithdrawalProcessed(
        bytes32 indexed withdrawalId,
        bytes32 indexed suiSender,
        address indexed recipient,
        address token,
        uint256 amount
    );

    event ValidatorRegistered(bytes32 indexed suiAddress, uint256 stake);

    event ValidatorRemoved(bytes32 indexed suiAddress);

    event CommitteeUpdated(
        uint64 indexed epoch,
        uint256 validatorCount,
        uint256 totalStake
    );

    event CheckpointSubmitted(
        uint64 indexed sequenceNumber,
        bytes32 indexed digest,
        uint64 epoch
    );

    event NullifierConsumed(
        bytes32 indexed suiNullifier,
        bytes32 indexed pilNullifier,
        bytes32 objectId
    );

    event TokenMappingAdded(
        bytes32 indexed suiCoinType,
        address indexed evmToken
    );

    event CircuitBreakerTriggered(uint256 anomalyCount);

    event CircuitBreakerReset();

    event RelayerRegistered(address indexed relayer, uint256 feeBps);

    event RelayerRemoved(address indexed relayer);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidValidator();
    error InsufficientStake();
    error InvalidSignature();
    error InvalidCheckpoint();
    error CheckpointAlreadyProcessed();
    error NullifierAlreadyConsumed();
    error DepositNotFound();
    error DepositAlreadyClaimed();
    error DepositAlreadyRefunded();
    error WithdrawalAlreadyProcessed();
    error InsufficientConfirmations();
    error CircuitBreakerActive();
    error DailyLimitExceeded();
    error TransferTooLarge();
    error InvalidToken();
    error InvalidAmount();
    error InvalidRecipient();
    error InvalidRelayerFee();
    error UnauthorizedRelayer();
    error InvalidEpoch();
    error QuorumNotMet();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier whenCircuitBreakerInactive() {
        if (circuitBreaker.triggered) {
            if (
                block.timestamp <
                circuitBreaker.triggeredAt + circuitBreaker.cooldownPeriod
            ) {
                revert CircuitBreakerActive();
            }
            // Auto-reset after cooldown
            circuitBreaker.triggered = false;
            emit CircuitBreakerReset();
        }
        _;
    }

    modifier withinLimits(uint256 amount, address user) {
        if (amount > MAX_TRANSFER) revert TransferTooLarge();

        uint256 today = block.timestamp / 1 days;
        if (dailyVolume[today] + amount > MAX_DAILY_VOLUME) {
            revert DailyLimitExceeded();
        }

        if (userDailyLimit[user] > 0) {
            if (userDailyVolume[user][today] + amount > userDailyLimit[user]) {
                revert DailyLimitExceeded();
            }
        }
        _;
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        uint64 initialEpoch
    ) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(BRIDGE_ADMIN_ROLE, admin);
        _grantRole(VALIDATOR_MANAGER_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);

        currentEpoch = initialEpoch;
        circuitBreaker.cooldownPeriod = 1 hours;
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a Sui validator
     * @param suiAddress Validator's Sui address
     * @param blsPublicKey BLS12-381 public key (96 bytes)
     * @param stake Validator's stake
     */
    function registerValidator(
        bytes32 suiAddress,
        bytes calldata blsPublicKey,
        uint256 stake
    ) external onlyRole(VALIDATOR_MANAGER_ROLE) {
        if (blsPublicKey.length != 96) revert InvalidValidator();
        if (stake == 0) revert InsufficientStake();

        validators[suiAddress] = SuiPrimitives.ValidatorInfo({
            suiAddress: suiAddress,
            blsPublicKey: blsPublicKey,
            networkPublicKey: "",
            stake: stake,
            commission: 0,
            activeSince: currentEpoch,
            isActive: true
        });

        activeValidators.push(suiAddress);
        emit ValidatorRegistered(suiAddress, stake);
    }

    /**
     * @notice Remove a validator
     */
    function removeValidator(
        bytes32 suiAddress
    ) external onlyRole(VALIDATOR_MANAGER_ROLE) {
        validators[suiAddress].isActive = false;

        // Remove from active list
        for (uint256 i = 0; i < activeValidators.length; i++) {
            if (activeValidators[i] == suiAddress) {
                activeValidators[i] = activeValidators[
                    activeValidators.length - 1
                ];
                activeValidators.pop();
                break;
            }
        }

        emit ValidatorRemoved(suiAddress);
    }

    /**
     * @notice Update validator committee for new epoch
     */
    function updateCommittee(
        uint64 epoch,
        bytes32[] calldata validatorAddresses,
        uint256[] calldata stakes
    ) external onlyRole(VALIDATOR_MANAGER_ROLE) {
        if (epoch <= currentEpoch) revert InvalidEpoch();
        if (validatorAddresses.length != stakes.length)
            revert InvalidValidator();

        uint256 totalStake = 0;
        for (uint256 i = 0; i < stakes.length; i++) {
            totalStake += stakes[i];
        }

        currentCommittee = SuiPrimitives.ValidatorCommittee({
            epoch: epoch,
            validators: validatorAddresses,
            stakes: stakes,
            totalStake: totalStake,
            committeeHash: SuiPrimitives.computeCommitteeHash(currentCommittee)
        });

        currentEpoch = epoch;
        emit CommitteeUpdated(epoch, validatorAddresses.length, totalStake);
    }

    // =========================================================================
    // CHECKPOINT MANAGEMENT
    // =========================================================================

    /**
     * @notice Submit a certified checkpoint
     * @param checkpoint Checkpoint summary
     * @param aggregatedSignature Aggregated BLS signature
     * @param signingValidators Validators that signed
     */
    function submitCheckpoint(
        SuiPrimitives.CheckpointSummary calldata checkpoint,
        bytes calldata aggregatedSignature,
        bytes32[] calldata signingValidators
    ) external onlyRole(RELAYER_ROLE) whenNotPaused whenCircuitBreakerInactive {
        bytes32 checkpointDigest = SuiPrimitives.computeCheckpointDigest(
            checkpoint
        );

        if (processedCheckpoints[checkpointDigest]) {
            revert CheckpointAlreadyProcessed();
        }

        // Verify checkpoint chain
        if (checkpoint.sequenceNumber > 0) {
            if (
                checkpoint.previousDigest !=
                checkpointDigests[checkpoint.sequenceNumber - 1]
            ) {
                revert InvalidCheckpoint();
            }
        }

        // Calculate signing stake
        uint256 signingStake = _calculateSigningStake(signingValidators);
        if (
            !SuiPrimitives.hasQuorum(signingStake, currentCommittee.totalStake)
        ) {
            revert QuorumNotMet();
        }

        // Verify BLS signature (stub - actual verification needs precompile)
        // In production, verify aggregatedSignature against signingValidators public keys

        // Store checkpoint
        checkpointDigests[checkpoint.sequenceNumber] = checkpointDigest;
        processedCheckpoints[checkpointDigest] = true;
        latestCheckpoint = checkpoint.sequenceNumber;

        emit CheckpointSubmitted(
            checkpoint.sequenceNumber,
            checkpointDigest,
            checkpoint.epoch
        );
    }

    /**
     * @notice Calculate total stake from signing validators
     */
    function _calculateSigningStake(
        bytes32[] calldata signingValidators
    ) internal view returns (uint256) {
        uint256 totalSigningStake = 0;
        for (uint256 i = 0; i < signingValidators.length; i++) {
            SuiPrimitives.ValidatorInfo storage validator = validators[
                signingValidators[i]
            ];
            if (validator.isActive) {
                totalSigningStake += validator.stake;
            }
        }
        return totalSigningStake;
    }

    // =========================================================================
    // DEPOSITS (EVM -> SUI)
    // =========================================================================

    /**
     * @notice Initiate a deposit to Sui
     * @param token EVM token address (address(0) for ETH)
     * @param amount Amount to deposit
     * @param suiRecipient Sui recipient address
     */
    function deposit(
        address token,
        uint256 amount,
        bytes32 suiRecipient
    )
        external
        payable
        nonReentrant
        whenNotPaused
        whenCircuitBreakerInactive
        withinLimits(amount, msg.sender)
    {
        if (suiRecipient == bytes32(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();

        if (token == address(0)) {
            if (msg.value != amount) revert InvalidAmount();
        } else {
            if (reverseTokenMappings[token] == bytes32(0))
                revert InvalidToken();
            // Transfer tokens from sender
            // IERC20(token).transferFrom(msg.sender, address(this), amount);
        }

        bytes32 depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                token,
                amount,
                suiRecipient,
                block.timestamp,
                block.number
            )
        );

        pendingDeposits[depositId] = DepositInfo({
            sender: msg.sender,
            token: token,
            amount: amount,
            suiRecipient: suiRecipient,
            timestamp: uint64(block.timestamp),
            claimed: false,
            refunded: false
        });

        // Update volume tracking
        uint256 today = block.timestamp / 1 days;
        dailyVolume[today] += amount;
        userDailyVolume[msg.sender][today] += amount;

        emit DepositInitiated(
            depositId,
            msg.sender,
            suiRecipient,
            token,
            amount
        );
    }

    /**
     * @notice Mark deposit as claimed on Sui side
     */
    function claimDeposit(
        bytes32 depositId,
        bytes32 suiTxDigest,
        bytes calldata /* proof */
    ) external onlyRole(RELAYER_ROLE) {
        DepositInfo storage info = pendingDeposits[depositId];
        if (info.sender == address(0)) revert DepositNotFound();
        if (info.claimed) revert DepositAlreadyClaimed();
        if (info.refunded) revert DepositAlreadyRefunded();

        info.claimed = true;
        emit DepositClaimed(depositId, suiTxDigest);
    }

    /**
     * @notice Refund expired deposit
     */
    function refundDeposit(bytes32 depositId) external nonReentrant {
        DepositInfo storage info = pendingDeposits[depositId];
        if (info.sender == address(0)) revert DepositNotFound();
        if (info.claimed) revert DepositAlreadyClaimed();
        if (info.refunded) revert DepositAlreadyRefunded();

        // Allow refund after 24 hours
        if (block.timestamp < info.timestamp + 24 hours) {
            revert InsufficientConfirmations();
        }

        info.refunded = true;

        if (info.token == address(0)) {
            (bool success, ) = info.sender.call{value: info.amount}("");
            require(success, "ETH refund failed");
        } else {
            // IERC20(info.token).transfer(info.sender, info.amount);
        }

        emit DepositRefunded(depositId, info.sender, info.amount);
    }

    // =========================================================================
    // WITHDRAWALS (SUI -> EVM)
    // =========================================================================

    /**
     * @notice Process a withdrawal from Sui
     * @param transfer Bridge transfer data from Sui
     * @param proof Merkle proof of inclusion in checkpoint
     * @param checkpointSeq Checkpoint sequence number
     */
    function processWithdrawal(
        SuiPrimitives.SuiBridgeTransfer calldata transfer,
        bytes32[] calldata proof,
        uint256[] calldata proofIndices,
        uint64 checkpointSeq,
        address relayer,
        uint256 relayerFeeBps
    )
        external
        nonReentrant
        whenNotPaused
        whenCircuitBreakerInactive
        withinLimits(transfer.amount, transfer.recipient)
    {
        // Verify checkpoint finality
        if (checkpointSeq > latestCheckpoint) {
            revert InsufficientConfirmations();
        }
        if (latestCheckpoint - checkpointSeq < MIN_CONFIRMATIONS) {
            revert InsufficientConfirmations();
        }

        // Compute transfer ID and check not already processed
        bytes32 transferId = SuiPrimitives.computeTransferId(transfer);
        if (completedWithdrawals[transferId].timestamp != 0) {
            revert WithdrawalAlreadyProcessed();
        }

        // Derive and check nullifier
        bytes32 suiNullifier = SuiPrimitives.deriveNullifier(
            transfer.sourceObject,
            0, // version would come from proof
            transfer.txDigest
        );

        if (consumedNullifiers[suiNullifier]) {
            revert NullifierAlreadyConsumed();
        }

        // Verify Merkle proof
        bytes32 checkpointRoot = checkpointDigests[checkpointSeq];
        bytes32 leaf = keccak256(
            abi.encodePacked(transfer.txDigest, transferId)
        );
        if (
            !SuiPrimitives.verifyMerkleProof(
                leaf,
                proof,
                proofIndices,
                checkpointRoot
            )
        ) {
            revert InvalidCheckpoint();
        }

        // Consume nullifier
        consumedNullifiers[suiNullifier] = true;

        // Create PIL binding
        bytes32 pilNullifier = SuiPrimitives.deriveCrossDomainNullifier(
            suiNullifier,
            SuiPrimitives.SUI_MAINNET,
            block.chainid
        );
        nullifierBindings[suiNullifier] = pilNullifier;

        // Calculate amounts
        address token = tokenMappings[transfer.coinType];
        uint256 amountAfterFee = transfer.amount;

        if (relayer != address(0)) {
            if (!relayers[relayer].isActive) revert UnauthorizedRelayer();
            if (relayerFeeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();

            uint256 relayerFee = (transfer.amount * relayerFeeBps) / 10000;
            amountAfterFee = transfer.amount - relayerFee;

            // Pay relayer
            if (token == address(0)) {
                (bool success, ) = relayer.call{value: relayerFee}("");
                require(success, "Relayer fee failed");
            }
            relayers[relayer].totalRelayed += transfer.amount;
            relayers[relayer].lastActive = block.timestamp;
        }

        // Record withdrawal
        completedWithdrawals[transferId] = WithdrawalInfo({
            suiSender: transfer.sender,
            recipient: transfer.recipient,
            token: token,
            amount: transfer.amount,
            txDigest: transfer.txDigest,
            epoch: transfer.sourceEpoch,
            timestamp: uint64(block.timestamp),
            nullifier: suiNullifier
        });

        // Update volume
        uint256 today = block.timestamp / 1 days;
        dailyVolume[today] += transfer.amount;

        // Transfer funds
        if (token == address(0)) {
            (bool success, ) = transfer.recipient.call{value: amountAfterFee}(
                ""
            );
            require(success, "ETH transfer failed");
        } else {
            // IERC20(token).transfer(transfer.recipient, amountAfterFee);
        }

        emit WithdrawalProcessed(
            transferId,
            transfer.sender,
            transfer.recipient,
            token,
            amountAfterFee
        );

        emit NullifierConsumed(
            suiNullifier,
            pilNullifier,
            transfer.sourceObject
        );
    }

    // =========================================================================
    // NULLIFIER FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if nullifier is consumed
     */
    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

    /**
     * @notice Get PIL binding for a Sui nullifier
     */
    function getPILBinding(
        bytes32 suiNullifier
    ) external view returns (bytes32) {
        return nullifierBindings[suiNullifier];
    }

    /**
     * @notice Verify nullifier binding consistency
     */
    function verifyNullifierBinding(
        bytes32 suiNullifier,
        bytes32 expectedPILBinding
    ) external view returns (bool) {
        bytes32 computed = SuiPrimitives.deriveCrossDomainNullifier(
            suiNullifier,
            SuiPrimitives.SUI_MAINNET,
            block.chainid
        );
        return computed == expectedPILBinding;
    }

    // =========================================================================
    // TOKEN MANAGEMENT
    // =========================================================================

    /**
     * @notice Add token mapping
     */
    function addTokenMapping(
        bytes32 suiCoinType,
        address evmToken
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        tokenMappings[suiCoinType] = evmToken;
        reverseTokenMappings[evmToken] = suiCoinType;
        emit TokenMappingAdded(suiCoinType, evmToken);
    }

    // =========================================================================
    // RELAYER MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a relayer
     */
    function registerRelayer(
        address relayer,
        uint256 feeBps
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        if (feeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();

        relayers[relayer] = RelayerInfo({
            isActive: true,
            feeBps: feeBps,
            totalRelayed: 0,
            lastActive: block.timestamp
        });

        _grantRole(RELAYER_ROLE, relayer);
        emit RelayerRegistered(relayer, feeBps);
    }

    /**
     * @notice Remove a relayer
     */
    function removeRelayer(
        address relayer
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        relayers[relayer].isActive = false;
        _revokeRole(RELAYER_ROLE, relayer);
        emit RelayerRemoved(relayer);
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    /**
     * @notice Trigger circuit breaker
     */
    function triggerCircuitBreaker() external onlyRole(EMERGENCY_ROLE) {
        circuitBreaker.triggered = true;
        circuitBreaker.triggeredAt = block.timestamp;
        circuitBreaker.anomalyCount++;
        circuitBreaker.lastAnomalyAt = block.timestamp;
        emit CircuitBreakerTriggered(circuitBreaker.anomalyCount);
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyRole(EMERGENCY_ROLE) {
        circuitBreaker.triggered = false;
        emit CircuitBreakerReset();
    }

    /**
     * @notice Update circuit breaker cooldown
     */
    function setCircuitBreakerCooldown(
        uint256 cooldown
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        circuitBreaker.cooldownPeriod = cooldown;
    }

    // =========================================================================
    // USER LIMITS
    // =========================================================================

    /**
     * @notice Set user daily limit
     */
    function setUserDailyLimit(
        address user,
        uint256 limit
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        userDailyLimit[user] = limit;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get validator count
     */
    function getValidatorCount() external view returns (uint256) {
        return activeValidators.length;
    }

    /**
     * @notice Get current committee info
     */
    function getCommitteeInfo()
        external
        view
        returns (uint64 epoch, uint256 validatorCount, uint256 totalStake)
    {
        return (
            currentCommittee.epoch,
            currentCommittee.validators.length,
            currentCommittee.totalStake
        );
    }

    /**
     * @notice Get checkpoint digest
     */
    function getCheckpointDigest(
        uint64 sequenceNumber
    ) external view returns (bytes32) {
        return checkpointDigests[sequenceNumber];
    }

    /**
     * @notice Get deposit info
     */
    function getDepositInfo(
        bytes32 depositId
    ) external view returns (DepositInfo memory) {
        return pendingDeposits[depositId];
    }

    /**
     * @notice Get withdrawal info
     */
    function getWithdrawalInfo(
        bytes32 transferId
    ) external view returns (WithdrawalInfo memory) {
        return completedWithdrawals[transferId];
    }

    /**
     * @notice Get daily volume
     */
    function getTodayVolume() external view returns (uint256) {
        return dailyVolume[block.timestamp / 1 days];
    }

    /**
     * @notice Get remaining daily limit
     */
    function getRemainingDailyLimit() external view returns (uint256) {
        uint256 today = block.timestamp / 1 days;
        uint256 used = dailyVolume[today];
        return used >= MAX_DAILY_VOLUME ? 0 : MAX_DAILY_VOLUME - used;
    }

    // =========================================================================
    // EMERGENCY
    // =========================================================================

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /**
     * @notice Emergency ETH withdrawal
     */
    function emergencyWithdraw(
        address to,
        uint256 amount
    ) external onlyRole(EMERGENCY_ROLE) {
        (bool success, ) = to.call{value: amount}("");
        require(success, "Emergency withdraw failed");
    }

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {}
}
