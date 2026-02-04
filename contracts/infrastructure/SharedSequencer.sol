// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SharedSequencer
 * @author Soul Protocol
 * @notice Shared sequencer infrastructure for multi-L2 coordination
 * @dev Enables atomic cross-L2 transactions with shared ordering guarantees
 *
 * SHARED SEQUENCER ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Shared Sequencer Infrastructure                       │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                    Sequencer Registry                            │    │
 * │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐     │    │
 * │  │  │ Sequencer │  │ Sequencer │  │ Sequencer │  │ Sequencer │     │    │
 * │  │  │    #1     │  │    #2     │  │    #3     │  │    #N     │     │    │
 * │  │  │ (Active)  │  │ (Standby) │  │ (Standby) │  │ (Standby) │     │    │
 * │  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘     │    │
 * │  │        │              │              │              │           │    │
 * │  │        └──────────────┴──────────────┴──────────────┘           │    │
 * │  │                           │                                     │    │
 * │  │                           ▼                                     │    │
 * │  │                 ┌─────────────────────┐                         │    │
 * │  │                 │   Rotation Engine   │                         │    │
 * │  │                 └─────────────────────┘                         │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                      Transaction Pool                            │    │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │    │
 * │  │  │   Pending   │──│   Ordered   │──│   Finalized │              │    │
 * │  │  │     Txs     │  │     Txs     │  │     Txs     │              │    │
 * │  │  └─────────────┘  └─────────────┘  └─────────────┘              │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                              │                                          │
 * │                              ▼                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                        L2 Chains                                 │    │
 * │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │    │
 * │  │  │Arbitrum │  │Optimism │  │  Base   │  │Starknet │            │    │
 * │  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY PROPERTIES:
 * - Stake-weighted sequencer selection
 * - Slashing for misbehavior
 * - Rotation to prevent centralization
 * - Atomic cross-L2 ordering guarantees
 */
contract SharedSequencer is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Sequencer status
    enum SequencerStatus {
        UNREGISTERED,
        PENDING,
        ACTIVE,
        STANDBY,
        JAILED,
        EXITING,
        EXITED
    }

    /// @notice Chain type for L2 support
    enum ChainType {
        ARBITRUM,
        OPTIMISM,
        BASE,
        ZKSYNC,
        STARKNET,
        SCROLL,
        LINEA,
        POLYGON_ZKEVM
    }

    /// @notice Sequencer registration
    struct Sequencer {
        address operator;
        address signer; // Key for signing blocks
        uint256 stake;
        uint256 registeredAt;
        uint256 lastActiveSlot;
        SequencerStatus status;
        // Performance metrics
        uint256 blocksProduced;
        uint256 blocksMissed;
        uint256 slashingPoints;
        // Supported chains
        ChainType[] supportedChains;
        // Exit data
        uint256 exitInitiatedAt;
        uint256 unstakeAmount;
    }

    /// @notice Sequencer slot assignment
    struct SlotAssignment {
        uint256 slotNumber;
        address sequencer;
        uint256 startTime;
        uint256 endTime;
        bool completed;
        bytes32 commitmentHash; // Commitment to ordered transactions
    }

    /// @notice Cross-L2 transaction batch
    struct CrossL2Batch {
        bytes32 batchId;
        uint256 slotNumber;
        address sequencer;
        ChainType[] targetChains;
        bytes32[] transactionHashes;
        bytes32 orderingCommitment;
        uint256 submittedAt;
        bool finalized;
    }

    /// @notice Chain configuration
    struct ChainConfig {
        ChainType chainType;
        uint256 chainId;
        address bridgeAdapter;
        uint256 gasLimit;
        bool isActive;
        uint256 lastSyncedSlot;
    }

    /// @notice Slashing record
    struct SlashingRecord {
        address sequencer;
        uint256 amount;
        string reason;
        uint256 timestamp;
        bool executed;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum stake to become a sequencer
    uint256 public minimumStake;

    /// @notice Slot duration in seconds
    uint256 public slotDuration;

    /// @notice Current slot number
    uint256 public currentSlot;

    /// @notice Genesis slot timestamp
    uint256 public genesisSlotTime;

    /// @notice Active sequencer set size
    uint256 public activeSetSize;

    /// @notice Exit delay in seconds
    uint256 public constant EXIT_DELAY = 7 days;

    /// @notice Slashing percentage (basis points)
    uint256 public slashingPercentage;

    /// @notice Registered sequencers
    mapping(address => Sequencer) public sequencers;
    address[] public sequencerList;
    uint256 public totalSequencers;

    /// @notice Active sequencer set
    address[] public activeSequencers;

    /// @notice Slot assignments
    mapping(uint256 => SlotAssignment) public slotAssignments;

    /// @notice Cross-L2 batches
    mapping(bytes32 => CrossL2Batch) public batches;
    uint256 public totalBatches;

    /// @notice Chain configurations
    mapping(ChainType => ChainConfig) public chainConfigs;
    ChainType[] public supportedChains;

    /// @notice Slashing records
    mapping(bytes32 => SlashingRecord) public slashingRecords;
    uint256 public totalSlashings;

    /// @notice Randomness for sequencer selection
    bytes32 public lastRandomness;

    /// @notice Total staked amount
    uint256 public totalStaked;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event SequencerRegistered(
        address indexed sequencer,
        address signer,
        uint256 stake
    );

    event SequencerActivated(address indexed sequencer, uint256 slotNumber);

    event SequencerDeactivated(address indexed sequencer, string reason);

    event SlotAssigned(
        uint256 indexed slotNumber,
        address indexed sequencer,
        uint256 startTime,
        uint256 endTime
    );

    event BatchSubmitted(
        bytes32 indexed batchId,
        uint256 indexed slotNumber,
        address indexed sequencer,
        uint256 txCount
    );

    event BatchFinalized(bytes32 indexed batchId, bytes32 orderingProof);

    event SequencerSlashed(
        address indexed sequencer,
        uint256 amount,
        string reason
    );

    event SequencerExitInitiated(address indexed sequencer, uint256 exitTime);

    event SequencerExited(address indexed sequencer, uint256 unstakeAmount);

    event ChainConfigured(
        ChainType indexed chainType,
        uint256 chainId,
        address bridgeAdapter
    );

    event RotationTriggered(uint256 slotNumber, address[] newActiveSet);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InsufficientStake(uint256 provided, uint256 required);
    error SequencerNotRegistered(address sequencer);
    error SequencerAlreadyRegistered(address sequencer);
    error SequencerNotActive(address sequencer);
    error InvalidSlot(uint256 slot);
    error SlotNotAssigned(uint256 slot);
    error NotAssignedSequencer(address caller, address assigned);
    error BatchAlreadySubmitted(bytes32 batchId);
    error BatchNotFound(bytes32 batchId);
    error ChainNotSupported(ChainType chain);
    error ExitNotInitiated(address sequencer);
    error ExitDelayNotPassed(uint256 remaining);
    error InvalidSlashingAmount(uint256 amount);
    error SequencerJailed(address sequencer);
    error InvalidRandomness();
    error InactiveChain(ChainType chain);

    error StakeTooLow();
    error SlotTooShort();
    error ActiveSetTooSmall();
    error InvalidPercentage();
    error InvalidSigner();
    error NoChainsSpecified();
    error InvalidStatusForActivation();
    error AlreadyExiting();
    error TransferFailed();
    error SlotNotAdvanced();
    error AlreadyFinalized();
    error InvalidBridgeAdapter();
    error SetTooSmall();


    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint256 _minimumStake,
        uint256 _slotDuration,
        uint256 _activeSetSize,
        uint256 _slashingPercentage
    ) {
        if (_minimumStake < 1 ether) revert StakeTooLow();
        if (_slotDuration < 1 seconds) revert SlotTooShort();
        if (_activeSetSize < 1) revert ActiveSetTooSmall();
        if (_slashingPercentage > 10000) revert InvalidPercentage();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, msg.sender);

        minimumStake = _minimumStake;
        slotDuration = _slotDuration;
        activeSetSize = _activeSetSize;
        slashingPercentage = _slashingPercentage;

        genesisSlotTime = block.timestamp;
        currentSlot = 0;

        // Initialize randomness
        lastRandomness = keccak256(
            abi.encodePacked(block.timestamp, block.prevrandao, address(this))
        );
    }

    /*//////////////////////////////////////////////////////////////
                         SEQUENCER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a sequencer
     * @param signer Address to sign blocks
     * @param supportedChainsList Chains this sequencer can serve
     */
    function registerSequencer(
        address signer,
        ChainType[] calldata supportedChainsList
    ) external payable nonReentrant whenNotPaused {
        if (sequencers[msg.sender].status != SequencerStatus.UNREGISTERED) {
            revert SequencerAlreadyRegistered(msg.sender);
        }
        if (msg.value < minimumStake) {
            revert InsufficientStake(msg.value, minimumStake);
        }

        if (signer == address(0)) revert InvalidSigner();
        if (supportedChainsList.length == 0) revert NoChainsSpecified();

        // Validate all chains are supported
        for (uint256 i = 0; i < supportedChainsList.length; i++) {
            ChainConfig storage config = chainConfigs[supportedChainsList[i]];
            if (!config.isActive) {
                revert InactiveChain(supportedChainsList[i]);
            }
        }

        // Create sequencer record
        Sequencer storage seq = sequencers[msg.sender];
        seq.operator = msg.sender;
        seq.signer = signer;
        seq.stake = msg.value;
        seq.registeredAt = block.timestamp;
        seq.status = SequencerStatus.PENDING;
        seq.supportedChains = supportedChainsList;

        sequencerList.push(msg.sender);
        totalSequencers++;
        totalStaked += msg.value;

        emit SequencerRegistered(msg.sender, signer, msg.value);
    }

    /**
     * @notice Add more stake to existing registration
     */
    function addStake() external payable nonReentrant whenNotPaused {
        Sequencer storage seq = sequencers[msg.sender];
        if (seq.status == SequencerStatus.UNREGISTERED) {
            revert SequencerNotRegistered(msg.sender);
        }
        if (seq.status == SequencerStatus.JAILED) {
            revert SequencerJailed(msg.sender);
        }

        seq.stake += msg.value;
        totalStaked += msg.value;
    }

    /**
     * @notice Activate a pending sequencer
     * @param sequencer Address to activate
     */
    function activateSequencer(
        address sequencer
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused {
        Sequencer storage seq = sequencers[sequencer];
        if (seq.status == SequencerStatus.UNREGISTERED) {
            revert SequencerNotRegistered(sequencer);
        }
        if (seq.status == SequencerStatus.JAILED) {
            revert SequencerJailed(sequencer);
        }

        if (
            seq.status != SequencerStatus.PENDING &&
            seq.status != SequencerStatus.STANDBY
        ) revert InvalidStatusForActivation();

        seq.status = SequencerStatus.ACTIVE;

        // Add to active set if there's room
        if (activeSequencers.length < activeSetSize) {
            activeSequencers.push(sequencer);
        }

        emit SequencerActivated(sequencer, currentSlot);
    }

    /**
     * @notice Initiate sequencer exit
     */
    function initiateExit() external nonReentrant whenNotPaused {
        Sequencer storage seq = sequencers[msg.sender];
        if (seq.status == SequencerStatus.UNREGISTERED) {
            revert SequencerNotRegistered(msg.sender);
        }

        if (
            seq.status == SequencerStatus.EXITING ||
            seq.status == SequencerStatus.EXITED
        ) revert AlreadyExiting();

        seq.status = SequencerStatus.EXITING;
        seq.exitInitiatedAt = block.timestamp;
        seq.unstakeAmount = seq.stake;

        // Remove from active set
        _removeFromActiveSet(msg.sender);

        emit SequencerExitInitiated(msg.sender, seq.exitInitiatedAt);
    }

    /**
     * @notice Complete exit and withdraw stake
     */
    function completeExit() external nonReentrant {
        Sequencer storage seq = sequencers[msg.sender];
        if (seq.status != SequencerStatus.EXITING) {
            revert ExitNotInitiated(msg.sender);
        }

        uint256 exitTime = seq.exitInitiatedAt + EXIT_DELAY;
        if (block.timestamp < exitTime) {
            revert ExitDelayNotPassed(exitTime - block.timestamp);
        }

        uint256 amount = seq.unstakeAmount;
        seq.status = SequencerStatus.EXITED;
        seq.stake = 0;
        seq.unstakeAmount = 0;

        totalStaked -= amount;

        // Transfer stake back
        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit SequencerExited(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           SLOT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current slot based on time
     */
    function getCurrentSlot() public view returns (uint256) {
        if (block.timestamp < genesisSlotTime) return 0;
        return (block.timestamp - genesisSlotTime) / slotDuration;
    }

    /**
     * @notice Advance to next slot and assign sequencer
     */
    function advanceSlot() external whenNotPaused {
        uint256 newSlot = getCurrentSlot();
        if (newSlot <= currentSlot) revert SlotNotAdvanced();

        // Check if previous slot was completed
        SlotAssignment storage prevSlot = slotAssignments[currentSlot];
        if (
            prevSlot.sequencer != address(0) &&
            !prevSlot.completed &&
            currentSlot > 0
        ) {
            // Mark sequencer as missing block
            Sequencer storage seq = sequencers[prevSlot.sequencer];
            seq.blocksMissed++;
            seq.slashingPoints++;

            // Auto-slash if too many missed blocks
            if (seq.slashingPoints >= 3) {
                _jailSequencer(prevSlot.sequencer, "Too many missed blocks");
            }
        }

        currentSlot = newSlot;

        // Assign sequencer for new slot
        address assignedSequencer = _selectSequencer(newSlot);

        if (assignedSequencer != address(0)) {
            slotAssignments[newSlot] = SlotAssignment({
                slotNumber: newSlot,
                sequencer: assignedSequencer,
                startTime: genesisSlotTime + (newSlot * slotDuration),
                endTime: genesisSlotTime + ((newSlot + 1) * slotDuration),
                completed: false,
                commitmentHash: bytes32(0)
            });

            emit SlotAssigned(
                newSlot,
                assignedSequencer,
                slotAssignments[newSlot].startTime,
                slotAssignments[newSlot].endTime
            );
        }
    }

    /**
     * @notice Submit a batch of cross-L2 transactions
     * @param targetChains Chains included in this batch
     * @param transactionHashes Hashes of transactions in order
     * @param orderingCommitment Commitment to transaction ordering
     */
    function submitBatch(
        ChainType[] calldata targetChains,
        bytes32[] calldata transactionHashes,
        bytes32 orderingCommitment
    ) external nonReentrant whenNotPaused returns (bytes32) {
        uint256 slot = getCurrentSlot();
        SlotAssignment storage assignment = slotAssignments[slot];

        if (assignment.sequencer == address(0)) {
            revert SlotNotAssigned(slot);
        }
        if (msg.sender != assignment.sequencer) {
            revert NotAssignedSequencer(msg.sender, assignment.sequencer);
        }

        // Validate chains
        for (uint256 i = 0; i < targetChains.length; i++) {
            if (!chainConfigs[targetChains[i]].isActive) {
                revert InactiveChain(targetChains[i]);
            }
        }

        bytes32 batchId = keccak256(
            abi.encodePacked(
                slot,
                msg.sender,
                orderingCommitment,
                block.timestamp
            )
        );

        if (batches[batchId].batchId != bytes32(0)) {
            revert BatchAlreadySubmitted(batchId);
        }

        batches[batchId] = CrossL2Batch({
            batchId: batchId,
            slotNumber: slot,
            sequencer: msg.sender,
            targetChains: targetChains,
            transactionHashes: transactionHashes,
            orderingCommitment: orderingCommitment,
            submittedAt: block.timestamp,
            finalized: false
        });

        // Update slot commitment
        assignment.commitmentHash = orderingCommitment;
        assignment.completed = true;

        // Update sequencer stats
        Sequencer storage seq = sequencers[msg.sender];
        seq.blocksProduced++;
        seq.lastActiveSlot = slot;

        totalBatches++;

        emit BatchSubmitted(
            batchId,
            slot,
            msg.sender,
            transactionHashes.length
        );

        return batchId;
    }

    /**
     * @notice Finalize a batch after L2 confirmations
     * @param batchId Batch to finalize
     * @param orderingProof Proof of correct ordering on all chains
     */
    function finalizeBatch(
        bytes32 batchId,
        bytes32 orderingProof
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused {
        CrossL2Batch storage batch = batches[batchId];
        if (batch.batchId == bytes32(0)) {
            revert BatchNotFound(batchId);
        }
        if (batch.finalized) revert AlreadyFinalized();

        batch.finalized = true;

        // Update chain sync status
        for (uint256 i = 0; i < batch.targetChains.length; i++) {
            chainConfigs[batch.targetChains[i]].lastSyncedSlot = batch
                .slotNumber;
        }

        emit BatchFinalized(batchId, orderingProof);
    }

    /*//////////////////////////////////////////////////////////////
                              ROTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Trigger sequencer rotation
     * @dev Called periodically or when misbehavior is detected
     */
    function triggerRotation() external onlyRole(OPERATOR_ROLE) whenNotPaused {
        // Update randomness for fair selection
        lastRandomness = keccak256(
            abi.encodePacked(
                lastRandomness,
                block.timestamp,
                block.prevrandao,
                currentSlot
            )
        );

        // Rebuild active set
        _rebuildActiveSet();

        emit RotationTriggered(currentSlot, activeSequencers);
    }

    /*//////////////////////////////////////////////////////////////
                              SLASHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Slash a sequencer for misbehavior
     * @param sequencer Address to slash
     * @param reason Description of violation
     */
    function slashSequencer(
        address sequencer,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) whenNotPaused {
        Sequencer storage seq = sequencers[sequencer];
        if (seq.status == SequencerStatus.UNREGISTERED) {
            revert SequencerNotRegistered(sequencer);
        }

        uint256 slashAmount = (seq.stake * slashingPercentage) / 10000;
        if (slashAmount == 0) {
            revert InvalidSlashingAmount(slashAmount);
        }

        seq.stake -= slashAmount;
        totalStaked -= slashAmount;

        bytes32 slashId = keccak256(
            abi.encodePacked(sequencer, block.timestamp, reason)
        );

        slashingRecords[slashId] = SlashingRecord({
            sequencer: sequencer,
            amount: slashAmount,
            reason: reason,
            timestamp: block.timestamp,
            executed: true
        });

        totalSlashings++;

        // Jail if stake falls below minimum
        if (seq.stake < minimumStake) {
            _jailSequencer(sequencer, "Stake below minimum after slashing");
        }

        emit SequencerSlashed(sequencer, slashAmount, reason);
    }

    /*//////////////////////////////////////////////////////////////
                           CHAIN CONFIG
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure an L2 chain
     */
    function configureChain(
        ChainType chainType,
        uint256 chainId,
        address bridgeAdapter,
        uint256 gasLimit
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (bridgeAdapter == address(0)) revert InvalidBridgeAdapter();

        chainConfigs[chainType] = ChainConfig({
            chainType: chainType,
            chainId: chainId,
            bridgeAdapter: bridgeAdapter,
            gasLimit: gasLimit,
            isActive: true,
            lastSyncedSlot: 0
        });

        // Add to supported chains if not already
        bool exists = false;
        for (uint256 i = 0; i < supportedChains.length; i++) {
            if (supportedChains[i] == chainType) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            supportedChains.push(chainType);
        }

        emit ChainConfigured(chainType, chainId, bridgeAdapter);
    }

    /**
     * @notice Deactivate a chain
     */
    function deactivateChain(
        ChainType chainType
    ) external onlyRole(GOVERNANCE_ROLE) {
        chainConfigs[chainType].isActive = false;
    }

    /*//////////////////////////////////////////////////////////////
                            GOVERNANCE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update minimum stake requirement
     */
    function setMinimumStake(
        uint256 newMinimum
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (newMinimum < 0.1 ether) revert StakeTooLow();
        minimumStake = newMinimum;
    }

    /**
     * @notice Update slot duration
     */
    function setSlotDuration(
        uint256 newDuration
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (newDuration < 1 seconds) revert SlotTooShort();
        slotDuration = newDuration;
    }

    /**
     * @notice Update active set size
     */
    function setActiveSetSize(
        uint256 newSize
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (newSize < 1) revert SetTooSmall();
        activeSetSize = newSize;
    }

    /**
     * @notice Update slashing percentage
     */
    function setSlashingPercentage(
        uint256 newPercentage
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (newPercentage > 10000) revert InvalidPercentage();
        slashingPercentage = newPercentage;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get sequencer info
     */
    function getSequencer(
        address addr
    ) external view returns (Sequencer memory) {
        return sequencers[addr];
    }

    /**
     * @notice Get active sequencer set
     */
    function getActiveSequencers() external view returns (address[] memory) {
        return activeSequencers;
    }

    /**
     * @notice Get supported chains
     */
    function getSupportedChains() external view returns (ChainType[] memory) {
        return supportedChains;
    }

    /**
     * @notice Get batch info
     */
    function getBatch(
        bytes32 batchId
    ) external view returns (CrossL2Batch memory) {
        return batches[batchId];
    }

    /**
     * @notice Get slot assignment
     */
    function getSlotAssignment(
        uint256 slot
    ) external view returns (SlotAssignment memory) {
        return slotAssignments[slot];
    }

    /**
     * @notice Check if sequencer is eligible for rotation
     */
    function isEligibleForActiveSet(
        address sequencer
    ) public view returns (bool) {
        Sequencer storage seq = sequencers[sequencer];
        return
            seq.status == SequencerStatus.ACTIVE ||
            seq.status == SequencerStatus.STANDBY ||
            seq.status == SequencerStatus.PENDING;
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Select sequencer for a slot using weighted randomness
     */
    function _selectSequencer(uint256 slot) internal view returns (address) {
        if (activeSequencers.length == 0) return address(0);

        // Use slot and randomness for deterministic selection
        bytes32 selectionSeed = keccak256(
            abi.encodePacked(lastRandomness, slot)
        );
        uint256 totalWeight = 0;

        // Calculate total weight (stake-weighted)
        for (uint256 i = 0; i < activeSequencers.length; i++) {
            totalWeight += sequencers[activeSequencers[i]].stake;
        }

        if (totalWeight == 0) return address(0);

        uint256 target = uint256(selectionSeed) % totalWeight;
        uint256 cumulative = 0;

        for (uint256 i = 0; i < activeSequencers.length; i++) {
            cumulative += sequencers[activeSequencers[i]].stake;
            if (target < cumulative) {
                return activeSequencers[i];
            }
        }

        return activeSequencers[activeSequencers.length - 1];
    }

    /**
     * @notice Remove sequencer from active set
     */
    function _removeFromActiveSet(address sequencer) internal {
        for (uint256 i = 0; i < activeSequencers.length; i++) {
            if (activeSequencers[i] == sequencer) {
                activeSequencers[i] = activeSequencers[
                    activeSequencers.length - 1
                ];
                activeSequencers.pop();
                break;
            }
        }
    }

    /**
     * @notice Jail a sequencer
     */
    function _jailSequencer(address sequencer, string memory reason) internal {
        Sequencer storage seq = sequencers[sequencer];
        seq.status = SequencerStatus.JAILED;
        _removeFromActiveSet(sequencer);

        emit SequencerDeactivated(sequencer, reason);
    }

    /**
     * @notice Rebuild active set based on stake
     */
    function _rebuildActiveSet() internal {
        // Clear current active set
        delete activeSequencers;

        // Create array of eligible sequencers with stakes
        address[] memory eligible = new address[](sequencerList.length);
        uint256 eligibleCount = 0;

        for (uint256 i = 0; i < sequencerList.length; i++) {
            address seq = sequencerList[i];
            if (
                isEligibleForActiveSet(seq) &&
                sequencers[seq].stake >= minimumStake
            ) {
                eligible[eligibleCount] = seq;
                eligibleCount++;
            }
        }

        // Sort by stake (descending) - simple selection sort for small sets
        for (uint256 i = 0; i < eligibleCount && i < activeSetSize; i++) {
            uint256 maxIdx = i;
            for (uint256 j = i + 1; j < eligibleCount; j++) {
                if (
                    sequencers[eligible[j]].stake >
                    sequencers[eligible[maxIdx]].stake
                ) {
                    maxIdx = j;
                }
            }
            if (maxIdx != i) {
                address temp = eligible[i];
                eligible[i] = eligible[maxIdx];
                eligible[maxIdx] = temp;
            }
        }

        // Add top stakers to active set
        for (uint256 i = 0; i < eligibleCount && i < activeSetSize; i++) {
            activeSequencers.push(eligible[i]);
            sequencers[eligible[i]].status = SequencerStatus.ACTIVE;
        }

        // Mark remaining as standby
        for (uint256 i = activeSetSize; i < eligibleCount; i++) {
            sequencers[eligible[i]].status = SequencerStatus.STANDBY;
        }
    }
}
