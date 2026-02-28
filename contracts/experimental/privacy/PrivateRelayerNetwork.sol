// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ExperimentalFeatureGated} from "../ExperimentalFeatureGated.sol";
import {ExperimentalFeatureRegistry} from "../../security/ExperimentalFeatureRegistry.sol";

/**
 * @title PrivateRelayerNetwork
 * @author ZASEON
 * @notice Privacy-preserving relayer network with commit-reveal MEV protection
 * @dev Implements stake-weighted VRF-based relayer selection and stealth fee payments
 * @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
 *
 * PRIVACY-PRESERVING RELAY PROTOCOL:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Private Relayer Network                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  COMMIT-REVEAL MEV PROTECTION:                                          │
 * │  1. Relayer commits: H(intentHash || secret)                            │
 * │  2. Wait commitment period (1-3 blocks)                                 │
 * │  3. Relayer reveals: (intent, secret) → verifies H matches             │
 * │  4. Execute if valid, slash if invalid/late                             │
 * │                                                                          │
 * │  STAKE-WEIGHTED VRF SELECTION:                                          │
 * │  1. Each relayer has stake S_i, total stake S = sum(S_i)                │
 * │  2. VRF output determines selection range [0, S)                        │
 * │  3. Relayer i selected if sum(S_1..S_{i-1}) <= VRF < sum(S_1..S_i)      │
 * │  4. Higher stake = higher probability of selection                       │
 * │                                                                          │
 * │  STEALTH FEE PAYMENTS:                                                  │
 * │  - Fees paid to relayer's stealth addresses                             │
 * │  - Unlinkable payment trail                                              │
 * │  - Optional encrypted metadata for advanced routing                     │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract PrivateRelayerNetwork is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    ExperimentalFeatureGated
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Minimum stake required to become a relayer
    uint256 public constant MIN_STAKE = 1 ether;

    /// @notice Maximum stake considered for selection probability
    uint256 public constant MAX_STAKE = 100 ether;

    /// @notice Commitment window (blocks)
    uint256 public constant COMMITMENT_WINDOW = 3;

    /// @notice Reveal window after commitment (blocks)
    uint256 public constant REVEAL_WINDOW = 10;

    /// @notice Slash percentage for invalid reveals (basis points)
    uint256 public constant SLASH_PERCENTAGE = 1000; // 10%

    /// @notice Slash percentage for late reveals (basis points)
    uint256 public constant LATE_SLASH_PERCENTAGE = 500; // 5%

    /// @notice Minimum relayers for decentralization
    uint256 public constant MIN_RELAYERS = 3;

    /// @notice VRF domain separator
    bytes32 public constant VRF_DOMAIN = keccak256("Zaseon_RELAYER_VRF_V1");

    /// @notice Cooldown period after slashing
    uint256 public constant SLASH_COOLDOWN = 1 days;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum RelayerStatus {
        INACTIVE,
        ACTIVE,
        JAILED,
        EXITING
    }

    enum CommitmentStatus {
        NONE,
        COMMITTED,
        REVEALED,
        EXPIRED,
        SLASHED
    }

    enum RelayType {
        STANDARD,
        PRIORITY,
        PRIVATE,
        BATCH
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Relayer registration
     */
    struct Relayer {
        address relayerAddress;
        bytes stealthMetaAddress; // For receiving stealth fee payments
        uint256 stake;
        uint256 totalRelayed;
        uint256 successfulRelays;
        uint256 failedRelays;
        uint256 slashedAmount;
        uint256 rewardsEarned;
        RelayerStatus status;
        uint256 registeredAt;
        uint256 lastActiveAt;
        uint256 jailedUntil;
        uint256 exitRequestedAt;
        bytes32 vrfKeyHash; // For VRF verification
    }

    /**
     * @notice Commit-reveal commitment
     */
    struct Commitment {
        bytes32 commitmentHash;
        address relayer;
        uint256 commitBlock;
        uint256 revealDeadline;
        CommitmentStatus status;
        bytes32 intentHash; // Hash of relay intent
        uint256 stake; // Stake at time of commitment
    }

    /**
     * @notice Relay intent (revealed after commitment)
     */
    struct RelayIntent {
        bytes32 transferId;
        uint256 sourceChainId;
        uint256 targetChainId;
        bytes32 proofHash;
        bytes payload;
        uint256 fee;
        uint256 deadline;
        RelayType relayType;
        bytes encryptedMetadata; // For private relays
    }

    /**
     * @notice Stealth fee payment
     */
    struct StealthFeePayment {
        address stealthAddress;
        bytes ephemeralPubKey;
        uint256 amount;
        bytes32 transferId;
        uint256 timestamp;
    }

    /**
     * @notice VRF selection round
     */
    struct VRFRound {
        bytes32 roundId;
        bytes32 seed;
        bytes32 vrfOutput;
        address selectedRelayer;
        uint256 totalStake;
        uint256 timestamp;
        bool finalized;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice All relayers: address => relayer
    mapping(address => Relayer) public relayers;

    /// @notice Active relayer addresses
    address[] public activeRelayers;

    /// @notice Commitments: commitmentHash => commitment
    mapping(bytes32 => Commitment) public commitments;

    /// @notice Revealed intents: intentHash => intent
    mapping(bytes32 => RelayIntent) public revealedIntents;

    /// @notice Stealth fee payments: paymentId => payment
    mapping(bytes32 => StealthFeePayment) public stealthPayments;

    /// @notice VRF rounds: roundId => round
    mapping(bytes32 => VRFRound) public vrfRounds;

    /// @notice Current VRF round
    bytes32 public currentVRFRound;

    /// @notice Total stake in the network
    uint256 public totalStake;

    /// @notice Total relays processed
    uint256 public totalRelays;

    /// @notice Total fees collected
    uint256 public totalFees;

    /// @notice Protocol fee (basis points)
    uint256 public protocolFeeBps;

    /// @notice Protocol fee recipient
    address public protocolFeeRecipient;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event RelayerRegistered(
        address indexed relayer,
        uint256 stake,
        bytes stealthMetaAddress
    );

    event RelayerStakeUpdated(
        address indexed relayer,
        uint256 oldStake,
        uint256 newStake
    );

    event RelayerJailed(
        address indexed relayer,
        uint256 jailedUntil,
        string reason
    );

    event RelayerExitRequested(address indexed relayer, uint256 exitTime);

    event CommitmentSubmitted(
        bytes32 indexed commitmentHash,
        address indexed relayer,
        uint256 commitBlock
    );

    event IntentRevealed(
        bytes32 indexed commitmentHash,
        bytes32 indexed intentHash,
        address indexed relayer
    );

    event RelayExecuted(
        bytes32 indexed transferId,
        address indexed relayer,
        uint256 fee
    );

    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        string reason
    );

    event StealthFeePaid(
        bytes32 indexed paymentId,
        address indexed stealthAddress,
        uint256 amount
    );

    event VRFRoundStarted(bytes32 indexed roundId, bytes32 seed);

    event RelayerSelected(
        bytes32 indexed roundId,
        address indexed relayer,
        bytes32 vrfOutput
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InsufficientStake();
    error RelayerAlreadyRegistered();
    error RelayerNotFound();
    error RelayerNotActive();
    error RelayerJailedError();
    error InvalidCommitment();
    error CommitmentExpired();
    error RevealTooEarly();
    error RevealTooLate();
    error InvalidReveal();
    error IntentAlreadyRevealed();
    error NotSelectedRelayer();
    error InsufficientRelayers();
    error InvalidVRFProof();
    error ZeroAddress();
    error ZeroAmount();
    error ExitNotReady();
    error TransferFailed();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier onlyActiveRelayer() {
        if (relayers[msg.sender].status != RelayerStatus.ACTIVE) {
            revert RelayerNotActive();
        }
        _;
    }

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

        /**
     * @notice Initializes the operation
     * @param admin The admin bound
     * @param _protocolFeeRecipient The _protocol fee recipient
     * @param _protocolFeeBps The _protocol fee bps
     * @param _featureRegistry The _feature registry
     */
function initialize(
        address admin,
        address _protocolFeeRecipient,
        uint256 _protocolFeeBps,
        address _featureRegistry
    ) external initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        protocolFeeRecipient = _protocolFeeRecipient;
        protocolFeeBps = _protocolFeeBps;

        // Wire to ExperimentalFeatureRegistry
        if (_featureRegistry != address(0)) {
            _setFeatureRegistry(
                _featureRegistry,
                ExperimentalFeatureRegistry(_featureRegistry)
                    .PRIVATE_RELAYER_NETWORK()
            );
        }
    }

    // =========================================================================
    // RELAYER REGISTRATION
    // =========================================================================

    /**
     * @notice Register as a relayer
     * @param stealthMetaAddress Stealth meta-address for receiving fees
     * @param vrfKeyHash VRF verification key hash
     */
    function registerRelayer(
        bytes calldata stealthMetaAddress,
        bytes32 vrfKeyHash
    ) external payable nonReentrant {
        if (msg.value < MIN_STAKE) revert InsufficientStake();
        if (relayers[msg.sender].status != RelayerStatus.INACTIVE) {
            revert RelayerAlreadyRegistered();
        }

        uint256 effectiveStake = msg.value > MAX_STAKE ? MAX_STAKE : msg.value;

        relayers[msg.sender] = Relayer({
            relayerAddress: msg.sender,
            stealthMetaAddress: stealthMetaAddress,
            stake: msg.value,
            totalRelayed: 0,
            successfulRelays: 0,
            failedRelays: 0,
            slashedAmount: 0,
            rewardsEarned: 0,
            status: RelayerStatus.ACTIVE,
            registeredAt: block.timestamp,
            lastActiveAt: block.timestamp,
            jailedUntil: 0,
            exitRequestedAt: 0,
            vrfKeyHash: vrfKeyHash
        });

        activeRelayers.push(msg.sender);
        totalStake += effectiveStake;

        _grantRole(RELAYER_ROLE, msg.sender);

        emit RelayerRegistered(msg.sender, msg.value, stealthMetaAddress);
    }

    /**
     * @notice Add stake to existing registration
     */
    function addStake() external payable onlyActiveRelayer nonReentrant {
        if (msg.value == 0) revert ZeroAmount();

        Relayer storage relayer = relayers[msg.sender];
        uint256 oldStake = relayer.stake;
        relayer.stake += msg.value;

        uint256 oldEffective = oldStake > MAX_STAKE ? MAX_STAKE : oldStake;
        uint256 newEffective = relayer.stake > MAX_STAKE
            ? MAX_STAKE
            : relayer.stake;
        totalStake = totalStake - oldEffective + newEffective;

        emit RelayerStakeUpdated(msg.sender, oldStake, relayer.stake);
    }

    /**
     * @notice Request to exit the relayer network
     */
    function requestExit() external onlyActiveRelayer {
        Relayer storage relayer = relayers[msg.sender];
        relayer.status = RelayerStatus.EXITING;
        relayer.exitRequestedAt = block.timestamp;

        emit RelayerExitRequested(msg.sender, block.timestamp + 7 days);
    }

    /**
     * @notice Complete exit and withdraw stake
     */
    function completeExit() external nonReentrant {
        Relayer storage relayer = relayers[msg.sender];
        if (relayer.status != RelayerStatus.EXITING) revert RelayerNotFound();
        if (block.timestamp < relayer.exitRequestedAt + 7 days) {
            revert ExitNotReady();
        }

        uint256 stake = relayer.stake;
        relayer.stake = 0;
        relayer.status = RelayerStatus.INACTIVE;

        uint256 effectiveStake = stake > MAX_STAKE ? MAX_STAKE : stake;
        totalStake -= effectiveStake;

        _removeFromActiveRelayers(msg.sender);
        _revokeRole(RELAYER_ROLE, msg.sender);

        (bool success, ) = msg.sender.call{value: stake}("");
        if (!success) revert TransferFailed();
    }

    // =========================================================================
    // COMMIT-REVEAL MECHANISM
    // =========================================================================

    /**
     * @notice Submit a commitment for relay intent
     * @param commitmentHash Hash of (intentHash || secret)
     */
    function submitCommitment(
        bytes32 commitmentHash
    ) external onlyActiveRelayer {
        if (commitments[commitmentHash].status != CommitmentStatus.NONE) {
            revert InvalidCommitment();
        }

        Relayer storage relayer = relayers[msg.sender];

        commitments[commitmentHash] = Commitment({
            commitmentHash: commitmentHash,
            relayer: msg.sender,
            commitBlock: block.number,
            revealDeadline: block.number + COMMITMENT_WINDOW + REVEAL_WINDOW,
            status: CommitmentStatus.COMMITTED,
            intentHash: bytes32(0),
            stake: relayer.stake
        });

        emit CommitmentSubmitted(commitmentHash, msg.sender, block.number);
    }

    /**
     * @notice Reveal a previously committed intent
     * @dev Commitment scheme: commitmentHash = keccak256(abi.encodePacked(intentHash, secret))
     *      The intentHash is computed as keccak256(abi.encode(intent)).
     *      SECURITY FIX: Removed block.timestamp from hash — it differs between commit and reveal
     *      blocks, making the original scheme permanently non-functional.
     * @param secret The secret used in commitment
     * @param intent The relay intent
     */
    function revealIntent(
        bytes32 secret,
        RelayIntent calldata intent
    ) external onlyActiveRelayer nonReentrant {
        bytes32 intentHash = keccak256(abi.encode(intent));
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(intentHash, secret)
        );

        Commitment storage commitment = commitments[commitmentHash];

        if (commitment.relayer != msg.sender) revert InvalidCommitment();
        if (commitment.status != CommitmentStatus.COMMITTED) {
            revert InvalidCommitment();
        }
        if (block.number < commitment.commitBlock + COMMITMENT_WINDOW) {
            revert RevealTooEarly();
        }
        if (block.number > commitment.revealDeadline) {
            // Late reveal - slash relayer
            _slashRelayer(msg.sender, LATE_SLASH_PERCENTAGE, "Late reveal");
            commitment.status = CommitmentStatus.EXPIRED;
            revert RevealTooLate();
        }

        commitment.status = CommitmentStatus.REVEALED;
        commitment.intentHash = intentHash;
        revealedIntents[intentHash] = intent;

        relayers[msg.sender].lastActiveAt = block.timestamp;

        emit IntentRevealed(commitmentHash, intentHash, msg.sender);
    }

    /**
     * @notice Execute a revealed relay intent
     * @param intentHash Hash of the intent to execute

     */
    function executeRelay(
        bytes32 intentHash,
        bytes calldata /* executionProof */
    ) external onlyActiveRelayer nonReentrant {
        RelayIntent storage intent = revealedIntents[intentHash];
        if (intent.transferId == bytes32(0)) revert InvalidReveal();
        if (block.timestamp > intent.deadline) revert CommitmentExpired();

        // Verify relayer is selected (simplified - in production use VRF)
        // For now, any active relayer can execute

        // Execute relay logic would go here
        // In production, this calls the bridge contracts

        Relayer storage relayer = relayers[msg.sender];
        relayer.totalRelayed++;
        relayer.successfulRelays++;
        relayer.lastActiveAt = block.timestamp;

        uint256 protocolFee = (intent.fee * protocolFeeBps) / 10000;
        uint256 relayerFee = intent.fee - protocolFee;

        relayer.rewardsEarned += relayerFee;
        totalRelays++;
        totalFees += intent.fee;

        // Pay relayer via stealth address (simplified)
        emit RelayExecuted(intent.transferId, msg.sender, relayerFee);
    }

    // =========================================================================
    // VRF-BASED SELECTION
    // =========================================================================

    /**
     * @notice Start a new VRF selection round
     * @param seed Random seed for VRF
     */
    function startVRFRound(bytes32 seed) external onlyRole(OPERATOR_ROLE) {
        if (activeRelayers.length < MIN_RELAYERS) revert InsufficientRelayers();

        bytes32 roundId = keccak256(
            abi.encodePacked(VRF_DOMAIN, seed, block.number)
        );

        vrfRounds[roundId] = VRFRound({
            roundId: roundId,
            seed: seed,
            vrfOutput: bytes32(0),
            selectedRelayer: address(0),
            totalStake: totalStake,
            timestamp: block.timestamp,
            finalized: false
        });

        currentVRFRound = roundId;

        emit VRFRoundStarted(roundId, seed);
    }

    /**
     * @notice Select relayer using VRF output
     * @param roundId The VRF round ID
     * @param vrfOutput The VRF output (verified externally)
     */
    function selectRelayer(
        bytes32 roundId,
        bytes32 vrfOutput
    ) external onlyRole(OPERATOR_ROLE) {
        VRFRound storage round = vrfRounds[roundId];
        if (round.finalized) revert InvalidVRFProof();

        round.vrfOutput = vrfOutput;

        // Stake-weighted selection
        uint256 selectionPoint = uint256(vrfOutput) % totalStake;
        uint256 cumulativeStake = 0;

        address selectedRelayer = address(0);
        for (uint256 i = 0; i < activeRelayers.length; ) {
            Relayer storage r = relayers[activeRelayers[i]];
            if (r.status == RelayerStatus.ACTIVE) {
                uint256 effectiveStake = r.stake > MAX_STAKE
                    ? MAX_STAKE
                    : r.stake;
                cumulativeStake += effectiveStake;
                if (selectionPoint < cumulativeStake) {
                    selectedRelayer = activeRelayers[i];
                    break;
                }
            }
            unchecked {
                ++i;
            }
        }

        round.selectedRelayer = selectedRelayer;
        round.finalized = true;

        emit RelayerSelected(roundId, selectedRelayer, vrfOutput);
    }

    /**
     * @notice Get currently selected relayer for a round
          * @param roundId The roundId identifier
     * @return The result value
     */
    function getSelectedRelayer(
        bytes32 roundId
    ) external view returns (address) {
        return vrfRounds[roundId].selectedRelayer;
    }

    // =========================================================================
    // STEALTH FEE PAYMENTS
    // =========================================================================

    /**
     * @notice Pay relayer fee to stealth address

     * @param stealthAddress The derived stealth address
     * @param ephemeralPubKey The ephemeral public key for stealth derivation
     * @param transferId Associated transfer ID
     */
    function payStealthFee(
        address /* relayerAddress */,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes32 transferId
    ) external payable nonReentrant {
        if (stealthAddress == address(0)) revert ZeroAddress();
        if (msg.value == 0) revert ZeroAmount();

        bytes32 paymentId = keccak256(
            abi.encodePacked(
                stealthAddress,
                ephemeralPubKey,
                transferId,
                block.timestamp
            )
        );

        stealthPayments[paymentId] = StealthFeePayment({
            stealthAddress: stealthAddress,
            ephemeralPubKey: ephemeralPubKey,
            amount: msg.value,
            transferId: transferId,
            timestamp: block.timestamp
        });

        (bool success, ) = stealthAddress.call{value: msg.value}("");
        if (!success) revert TransferFailed();

        emit StealthFeePaid(paymentId, stealthAddress, msg.value);
    }

    // =========================================================================
    // SLASHING
    // =========================================================================

    /**
     * @notice Slash a relayer for misbehavior
     * @dev Current implementation relies on trusted SLASHER_ROLE.
     *      V2 Enhancement: Add cryptographic fraud proof verification:
     *      - ZK proof of invalid relay behavior
     *      - Merkle proof of commitment/reveal mismatch
     *      - Signature proof of censorship or double-processing
     *      This would enable permissionless slashing with on-chain evidence.
     * @param relayerAddress The relayer to slash
     * @param reason Human-readable reason for the slash
     */
    function slashRelayer(
        address relayerAddress,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) {
        _slashRelayer(relayerAddress, SLASH_PERCENTAGE, reason);
    }

    function _slashRelayer(
        address relayerAddress,
        uint256 slashBps,
        string memory reason
    ) internal {
        Relayer storage relayer = relayers[relayerAddress];
        if (relayer.status == RelayerStatus.INACTIVE) revert RelayerNotFound();

        uint256 slashAmount = (relayer.stake * slashBps) / 10000;
        relayer.stake -= slashAmount;
        relayer.slashedAmount += slashAmount;
        relayer.failedRelays++;

        // Jail relayer
        relayer.status = RelayerStatus.JAILED;
        relayer.jailedUntil = block.timestamp + SLASH_COOLDOWN;

        // Update total stake
        uint256 effectiveSlash = slashAmount > MAX_STAKE
            ? MAX_STAKE
            : slashAmount;
        totalStake -= effectiveSlash;

        emit RelayerSlashed(relayerAddress, slashAmount, reason);
        emit RelayerJailed(relayerAddress, relayer.jailedUntil, reason);
    }

    /**
     * @notice Unjail a relayer after cooldown
     */
    function unjailRelayer() external {
        Relayer storage relayer = relayers[msg.sender];
        if (relayer.status != RelayerStatus.JAILED) revert RelayerNotFound();
        if (block.timestamp < relayer.jailedUntil) revert RelayerJailedError();

        relayer.status = RelayerStatus.ACTIVE;
        relayer.jailedUntil = 0;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

        /**
     * @notice Returns the relayer count
     * @return The result value
     */
function getRelayerCount() external view returns (uint256) {
        return activeRelayers.length;
    }

        /**
     * @notice Returns the relayer info
     * @param relayerAddress The relayer address
     * @return The result value
     */
function getRelayerInfo(
        address relayerAddress
    ) external view returns (Relayer memory) {
        return relayers[relayerAddress];
    }

        /**
     * @notice Returns the active relayers
     * @return The result value
     */
function getActiveRelayers() external view returns (address[] memory) {
        return activeRelayers;
    }

        /**
     * @notice Returns the commitment
     * @param commitmentHash The commitmentHash hash value
     * @return The result value
     */
function getCommitment(
        bytes32 commitmentHash
    ) external view returns (Commitment memory) {
        return commitments[commitmentHash];
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _removeFromActiveRelayers(address relayerAddress) internal {
        for (uint256 i = 0; i < activeRelayers.length; ) {
            if (activeRelayers[i] == relayerAddress) {
                activeRelayers[i] = activeRelayers[activeRelayers.length - 1];
                activeRelayers.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {}
}
