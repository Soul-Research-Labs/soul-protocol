// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "../sei/SeiPrimitives.sol";

/**
 * @title SeiBridgeAdapter
 * @notice Bridge adapter for Sei blockchain integration with PIL
 * @dev Implements:
 *      - Tendermint BFT validator management
 *      - IBC channel support
 *      - Fast finality (~400ms) verification
 *      - Cross-domain nullifier binding
 *      - Rate limiting and circuit breaker
 */
contract SeiBridgeAdapter is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SeiPrimitives for *;

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
    uint256 private constant MIN_CONFIRMATIONS = 1; // Fast finality
    uint256 private constant MAX_RELAYER_FEE_BPS = 500; // 5%
    uint256 private constant BLOCK_HISTORY_SIZE = 1000;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Current validator set hash
    bytes32 public validatorSetHash;

    /// @notice Total voting power of current validator set
    uint256 public totalVotingPower;

    /// @notice Validator info mapping
    mapping(bytes32 => SeiPrimitives.ValidatorInfo) public validators;

    /// @notice Active validator addresses
    bytes32[] public activeValidators;

    /// @notice Block header history (height => hash)
    mapping(int64 => bytes32) public blockHashes;

    /// @notice Latest finalized block height
    int64 public latestHeight;

    /// @notice IBC channels (channelId hash => channel)
    mapping(bytes32 => SeiPrimitives.IBCChannel) public ibcChannels;

    /// @notice Active IBC channel IDs
    bytes32[] public activeChannels;

    /// @notice Consumed nullifiers
    mapping(bytes32 => bool) public consumedNullifiers;

    /// @notice PIL nullifier bindings (seiNullifier => pilNullifier)
    mapping(bytes32 => bytes32) public nullifierBindings;

    /// @notice Pending deposits (EVM -> Sei)
    mapping(bytes32 => DepositInfo) public pendingDeposits;

    /// @notice Completed withdrawals (Sei -> EVM)
    mapping(bytes32 => WithdrawalInfo) public completedWithdrawals;

    /// @notice Daily volume tracking
    mapping(uint256 => uint256) public dailyVolume;

    /// @notice User daily limits
    mapping(address => mapping(uint256 => uint256)) public userDailyVolume;
    mapping(address => uint256) public userDailyLimit;

    /// @notice Supported token mappings (Sei denom hash => EVM token)
    mapping(bytes32 => address) public tokenMappings;

    /// @notice Reverse token mappings (EVM token => Sei denom)
    mapping(address => string) public reverseTokenMappings;

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
        bytes32 seiRecipient;
        uint64 timestamp;
        bool claimed;
        bool refunded;
    }

    struct WithdrawalInfo {
        bytes32 seiSender;
        address recipient;
        address token;
        uint256 amount;
        bytes32 txHash;
        int64 height;
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
        bytes32 indexed seiRecipient,
        address token,
        uint256 amount
    );

    event DepositClaimed(bytes32 indexed depositId, bytes32 seiTxHash);

    event DepositRefunded(
        bytes32 indexed depositId,
        address sender,
        uint256 amount
    );

    event WithdrawalProcessed(
        bytes32 indexed withdrawalId,
        bytes32 indexed seiSender,
        address indexed recipient,
        address token,
        uint256 amount
    );

    event ValidatorRegistered(
        bytes32 indexed operatorAddress,
        uint256 votingPower
    );

    event ValidatorRemoved(bytes32 indexed operatorAddress);

    event ValidatorSetUpdated(
        bytes32 indexed validatorSetHash,
        uint256 validatorCount,
        uint256 totalPower
    );

    event BlockFinalized(
        int64 indexed height,
        bytes32 indexed blockHash,
        uint256 signingPower
    );

    event IBCChannelRegistered(
        bytes32 indexed channelHash,
        string channelId,
        string counterpartyChannelId
    );

    event NullifierConsumed(
        bytes32 indexed seiNullifier,
        bytes32 indexed pilNullifier,
        bytes32 txHash
    );

    event TokenMappingAdded(
        bytes32 indexed denomHash,
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
    error InsufficientVotingPower();
    error InvalidSignature();
    error InvalidBlock();
    error BlockAlreadyFinalized();
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
    error InvalidHeight();
    error FinalityNotMet();
    error InvalidIBCChannel();

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

    function initialize(address admin) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(BRIDGE_ADMIN_ROLE, admin);
        _grantRole(VALIDATOR_MANAGER_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);

        circuitBreaker.cooldownPeriod = 1 hours;
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a Sei validator
     * @param operatorAddress Validator operator address hash
     * @param pubKey secp256k1 public key (33 bytes compressed)
     * @param votingPower Validator voting power
     */
    function registerValidator(
        bytes32 operatorAddress,
        bytes calldata pubKey,
        uint256 votingPower
    ) external onlyRole(VALIDATOR_MANAGER_ROLE) {
        if (pubKey.length != 33) revert InvalidValidator();
        if (votingPower == 0) revert InsufficientVotingPower();

        validators[operatorAddress] = SeiPrimitives.ValidatorInfo({
            operatorAddress: operatorAddress,
            pubKey: pubKey,
            votingPower: votingPower,
            commission: 0,
            jailed: false,
            active: true
        });

        activeValidators.push(operatorAddress);
        totalVotingPower += votingPower;

        emit ValidatorRegistered(operatorAddress, votingPower);
    }

    /**
     * @notice Remove a validator
     */
    function removeValidator(
        bytes32 operatorAddress
    ) external onlyRole(VALIDATOR_MANAGER_ROLE) {
        SeiPrimitives.ValidatorInfo storage validator = validators[
            operatorAddress
        ];
        if (validator.active) {
            totalVotingPower -= validator.votingPower;
        }
        validator.active = false;

        // Remove from active list
        for (uint256 i = 0; i < activeValidators.length; i++) {
            if (activeValidators[i] == operatorAddress) {
                activeValidators[i] = activeValidators[
                    activeValidators.length - 1
                ];
                activeValidators.pop();
                break;
            }
        }

        emit ValidatorRemoved(operatorAddress);
    }

    /**
     * @notice Update validator set
     */
    function updateValidatorSet(
        bytes32[] calldata operatorAddresses,
        bytes[] calldata pubKeys,
        uint256[] calldata votingPowers
    ) external onlyRole(VALIDATOR_MANAGER_ROLE) {
        if (
            operatorAddresses.length != pubKeys.length ||
            operatorAddresses.length != votingPowers.length
        ) {
            revert InvalidValidator();
        }

        // Clear existing validators
        for (uint256 i = 0; i < activeValidators.length; i++) {
            validators[activeValidators[i]].active = false;
        }
        delete activeValidators;
        totalVotingPower = 0;

        // Add new validators
        for (uint256 i = 0; i < operatorAddresses.length; i++) {
            if (pubKeys[i].length != 33) revert InvalidValidator();

            validators[operatorAddresses[i]] = SeiPrimitives.ValidatorInfo({
                operatorAddress: operatorAddresses[i],
                pubKey: pubKeys[i],
                votingPower: votingPowers[i],
                commission: 0,
                jailed: false,
                active: true
            });

            activeValidators.push(operatorAddresses[i]);
            totalVotingPower += votingPowers[i];
        }

        validatorSetHash = _computeValidatorSetHash();

        emit ValidatorSetUpdated(
            validatorSetHash,
            operatorAddresses.length,
            totalVotingPower
        );
    }

    /**
     * @notice Compute current validator set hash
     */
    function _computeValidatorSetHash() internal view returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](activeValidators.length);
        for (uint256 i = 0; i < activeValidators.length; i++) {
            SeiPrimitives.ValidatorInfo storage v = validators[
                activeValidators[i]
            ];
            hashes[i] = sha256(
                abi.encodePacked(v.operatorAddress, v.pubKey, v.votingPower)
            );
        }
        return SeiPrimitives.hashN(hashes);
    }

    // =========================================================================
    // BLOCK FINALIZATION
    // =========================================================================

    /**
     * @notice Submit a finalized block header
     * @param header Block header
     * @param commit Block commit with signatures
     */
    function submitBlock(
        SeiPrimitives.BlockHeader calldata header,
        SeiPrimitives.Commit calldata commit
    ) external onlyRole(RELAYER_ROLE) whenNotPaused whenCircuitBreakerInactive {
        if (header.height <= latestHeight) revert BlockAlreadyFinalized();

        bytes32 blockHash = SeiPrimitives.computeBlockHash(header);

        // Verify commit references this block
        if (commit.height != header.height) revert InvalidBlock();
        if (commit.blockId != blockHash) revert InvalidBlock();

        // Verify finality (2/3 + 1 voting power)
        uint256 signingPower = _calculateSigningPower(commit);
        if (!SeiPrimitives.hasFinality(signingPower, totalVotingPower)) {
            revert FinalityNotMet();
        }

        // Store block
        blockHashes[header.height] = blockHash;
        latestHeight = header.height;

        emit BlockFinalized(header.height, blockHash, signingPower);
    }

    /**
     * @notice Calculate total signing power from commit
     */
    function _calculateSigningPower(
        SeiPrimitives.Commit calldata commit
    ) internal view returns (uint256) {
        uint256 power = 0;
        for (uint256 i = 0; i < commit.signatures.length; i++) {
            if (commit.signatures[i].forBlock) {
                SeiPrimitives.ValidatorInfo storage v = validators[
                    commit.signatures[i].validatorAddress
                ];
                if (v.active && !v.jailed) {
                    power += v.votingPower;
                }
            }
        }
        return power;
    }

    // =========================================================================
    // IBC CHANNEL MANAGEMENT
    // =========================================================================

    /**
     * @notice Register an IBC channel
     */
    function registerIBCChannel(
        string calldata channelId,
        string calldata portId,
        string calldata counterpartyChannelId,
        string calldata counterpartyPortId,
        string calldata connectionId
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        bytes32 channelHash = keccak256(abi.encodePacked(channelId));

        ibcChannels[channelHash] = SeiPrimitives.IBCChannel({
            channelId: channelId,
            portId: portId,
            counterpartyChannelId: counterpartyChannelId,
            counterpartyPortId: counterpartyPortId,
            connectionId: connectionId,
            state: 3, // OPEN
            ordering: 1 // UNORDERED
        });

        activeChannels.push(channelHash);

        emit IBCChannelRegistered(
            channelHash,
            channelId,
            counterpartyChannelId
        );
    }

    /**
     * @notice Close an IBC channel
     */
    function closeIBCChannel(
        bytes32 channelHash
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        ibcChannels[channelHash].state = 4; // CLOSED
    }

    // =========================================================================
    // DEPOSITS (EVM -> SEI)
    // =========================================================================

    /**
     * @notice Initiate a deposit to Sei
     * @param token EVM token address (address(0) for ETH)
     * @param amount Amount to deposit
     * @param seiRecipient Sei recipient address hash
     */
    function deposit(
        address token,
        uint256 amount,
        bytes32 seiRecipient
    )
        external
        payable
        nonReentrant
        whenNotPaused
        whenCircuitBreakerInactive
        withinLimits(amount, msg.sender)
    {
        if (seiRecipient == bytes32(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();

        if (token == address(0)) {
            if (msg.value != amount) revert InvalidAmount();
        } else {
            if (bytes(reverseTokenMappings[token]).length == 0)
                revert InvalidToken();
        }

        bytes32 depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                token,
                amount,
                seiRecipient,
                block.timestamp,
                block.number
            )
        );

        pendingDeposits[depositId] = DepositInfo({
            sender: msg.sender,
            token: token,
            amount: amount,
            seiRecipient: seiRecipient,
            timestamp: uint64(block.timestamp),
            claimed: false,
            refunded: false
        });

        uint256 today = block.timestamp / 1 days;
        dailyVolume[today] += amount;
        userDailyVolume[msg.sender][today] += amount;

        emit DepositInitiated(
            depositId,
            msg.sender,
            seiRecipient,
            token,
            amount
        );
    }

    /**
     * @notice Mark deposit as claimed on Sei side
     */
    function claimDeposit(
        bytes32 depositId,
        bytes32 seiTxHash,
        bytes calldata /* proof */
    ) external onlyRole(RELAYER_ROLE) {
        DepositInfo storage info = pendingDeposits[depositId];
        if (info.sender == address(0)) revert DepositNotFound();
        if (info.claimed) revert DepositAlreadyClaimed();
        if (info.refunded) revert DepositAlreadyRefunded();

        info.claimed = true;
        emit DepositClaimed(depositId, seiTxHash);
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
        }

        emit DepositRefunded(depositId, info.sender, info.amount);
    }

    // =========================================================================
    // WITHDRAWALS (SEI -> EVM)
    // =========================================================================

    /**
     * @notice Process a withdrawal from Sei
     * @param transfer Bridge transfer data from Sei
     * @param proof Merkle proof of inclusion
     * @param proofIndices Proof path indices
     * @param relayer Optional relayer address
     * @param relayerFeeBps Relayer fee in basis points
     */
    function processWithdrawal(
        SeiPrimitives.SeiBridgeTransfer calldata transfer,
        bytes32[] calldata proof,
        uint256[] calldata proofIndices,
        address relayer,
        uint256 relayerFeeBps
    )
        external
        nonReentrant
        whenNotPaused
        whenCircuitBreakerInactive
        withinLimits(transfer.amount, transfer.recipient)
    {
        // Verify block finality
        if (transfer.sourceHeight > latestHeight) {
            revert InsufficientConfirmations();
        }

        // Compute transfer ID and check not already processed
        bytes32 transferId = SeiPrimitives.computeTransferId(transfer);
        if (completedWithdrawals[transferId].timestamp != 0) {
            revert WithdrawalAlreadyProcessed();
        }

        // Derive and check nullifier
        bytes32 seiNullifier = SeiPrimitives.deriveNullifier(
            transfer.txHash,
            transfer.sourceHeight,
            0
        );

        if (consumedNullifiers[seiNullifier]) {
            revert NullifierAlreadyConsumed();
        }

        // Verify Merkle proof
        bytes32 blockRoot = blockHashes[transfer.sourceHeight];
        bytes32 leaf = sha256(abi.encodePacked(transfer.txHash, transferId));
        if (
            !SeiPrimitives.verifyMerkleProof(
                leaf,
                proof,
                proofIndices,
                blockRoot
            )
        ) {
            revert InvalidBlock();
        }

        // Consume nullifier
        consumedNullifiers[seiNullifier] = true;

        // Create PIL binding
        bytes32 pilNullifier = SeiPrimitives.deriveCrossDomainNullifier(
            seiNullifier,
            SeiPrimitives.SEI_MAINNET_NUMERIC,
            block.chainid
        );
        nullifierBindings[seiNullifier] = pilNullifier;

        // Calculate amounts
        bytes32 denomHash = keccak256(abi.encodePacked(transfer.denom));
        address token = tokenMappings[denomHash];
        uint256 amountAfterFee = transfer.amount;

        if (relayer != address(0)) {
            if (!relayers[relayer].isActive) revert UnauthorizedRelayer();
            if (relayerFeeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();

            uint256 relayerFee = (transfer.amount * relayerFeeBps) / 10000;
            amountAfterFee = transfer.amount - relayerFee;

            if (token == address(0)) {
                (bool success, ) = relayer.call{value: relayerFee}("");
                require(success, "Relayer fee failed");
            }
            relayers[relayer].totalRelayed += transfer.amount;
            relayers[relayer].lastActive = block.timestamp;
        }

        // Record withdrawal
        completedWithdrawals[transferId] = WithdrawalInfo({
            seiSender: transfer.sender,
            recipient: transfer.recipient,
            token: token,
            amount: transfer.amount,
            txHash: transfer.txHash,
            height: transfer.sourceHeight,
            timestamp: uint64(block.timestamp),
            nullifier: seiNullifier
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
        }

        emit WithdrawalProcessed(
            transferId,
            transfer.sender,
            transfer.recipient,
            token,
            amountAfterFee
        );

        emit NullifierConsumed(seiNullifier, pilNullifier, transfer.txHash);
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
     * @notice Get PIL binding for a Sei nullifier
     */
    function getPILBinding(
        bytes32 seiNullifier
    ) external view returns (bytes32) {
        return nullifierBindings[seiNullifier];
    }

    /**
     * @notice Verify nullifier binding consistency
     */
    function verifyNullifierBinding(
        bytes32 seiNullifier,
        bytes32 expectedPILBinding
    ) external view returns (bool) {
        bytes32 computed = SeiPrimitives.deriveCrossDomainNullifier(
            seiNullifier,
            SeiPrimitives.SEI_MAINNET_NUMERIC,
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
        string calldata seiDenom,
        address evmToken
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        bytes32 denomHash = keccak256(abi.encodePacked(seiDenom));
        tokenMappings[denomHash] = evmToken;
        reverseTokenMappings[evmToken] = seiDenom;
        emit TokenMappingAdded(denomHash, evmToken);
    }

    // =========================================================================
    // RELAYER MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a relayer
     */
    function registerRelayer(
        address relayerAddr,
        uint256 feeBps
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        if (feeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();

        relayers[relayerAddr] = RelayerInfo({
            isActive: true,
            feeBps: feeBps,
            totalRelayed: 0,
            lastActive: block.timestamp
        });

        _grantRole(RELAYER_ROLE, relayerAddr);
        emit RelayerRegistered(relayerAddr, feeBps);
    }

    /**
     * @notice Remove a relayer
     */
    function removeRelayer(
        address relayerAddr
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        relayers[relayerAddr].isActive = false;
        _revokeRole(RELAYER_ROLE, relayerAddr);
        emit RelayerRemoved(relayerAddr);
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
     * @notice Get validator set info
     */
    function getValidatorSetInfo()
        external
        view
        returns (bytes32 setHash, uint256 validatorCount, uint256 totalPower)
    {
        return (validatorSetHash, activeValidators.length, totalVotingPower);
    }

    /**
     * @notice Get block hash
     */
    function getBlockHash(int64 height) external view returns (bytes32) {
        return blockHashes[height];
    }

    /**
     * @notice Get IBC channel count
     */
    function getIBCChannelCount() external view returns (uint256) {
        return activeChannels.length;
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
