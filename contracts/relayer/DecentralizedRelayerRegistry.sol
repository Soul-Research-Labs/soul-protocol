// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title DecentralizedRelayerRegistry
 * @author Soul Protocol
 * @notice Permissionless registry for relayers with staking, slashing, and reward distribution
 * @dev Manages the lifecycle of relayers in the Soul Protocol relay network.
 *
 * ARCHITECTURE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                  RELAYER LIFECYCLE                                      │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  ┌──────────┐  register()  ┌──────────┐  initiateUnstake()            │
 * │  │UNREGISTERED├────────────►│  ACTIVE  ├──────────────────┐           │
 * │  └──────────┘  (≥10 ETH)   └────┬─────┘                  │           │
 * │                                  │                         ▼           │
 * │                     depositStake()│              ┌──────────────┐      │
 * │                     (add stake)   │              │  UNBONDING   │      │
 * │                                   │              │  (7 days)    │      │
 * │                                   │              └──────┬───────┘      │
 * │                     slash()       │                     │              │
 * │                     (reduce stake)│       withdrawStake()│             │
 * │                                   │                     ▼              │
 * │                                   │              ┌──────────────┐      │
 * │                                   │              │ UNREGISTERED │      │
 * │                                   │              └──────────────┘      │
 * │                                                                        │
 * │  REWARDS:  addReward() → accumulates → claimRewards() → transfer      │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY MODEL:
 * - Minimum stake of 10 ETH acts as Sybil resistance and economic security
 * - 7-day unbonding period allows slashing misbehavior before withdrawal
 * - SLASHER_ROLE is held by protocol governance/security module
 * - ReentrancyGuard on all ETH-transferring functions (CEI pattern)
 * - Rewards distributed via addReward(), claimed separately to prevent
 *   griefing through failed transfers
 */
contract DecentralizedRelayerRegistry is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role authorized to slash misbehaving relayers
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /// @notice Role for governance parameter updates
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum stake required for registration (10 ETH)
    /// @dev Acts as Sybil resistance — economic cost to operate a relayer
    uint256 public constant MIN_STAKE = 10 ether;

    /// @notice Time after initiateUnstake() before withdrawal is allowed
    /// @dev 7 days allows time for slashing evidence to be submitted
    uint256 public constant UNBONDING_PERIOD = 7 days;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice On-chain state for each registered relayer
    /// @param stake Current staked amount (decreases on slash, increases on deposit)
    /// @param rewards Accumulated unclaimed rewards
    /// @param unlockTime Timestamp when withdrawal is allowed (0 = active, >0 = unbonding)
    /// @param isRegistered Whether the relayer is registered in the system
    struct RelayerInfo {
        uint256 stake;
        uint256 rewards;
        uint256 unlockTime; // 0 if active, > 0 if unbonding
        bool isRegistered;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Relayer state indexed by address
    mapping(address => RelayerInfo) public relayers;

    /// @notice Array of all relayer addresses that have ever registered
    /// @dev Used for off-chain enumeration; entries are not removed on unregister
    address[] public activeRelayers;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a new relayer registers with their initial stake
    event RelayerRegistered(address indexed relayer, uint256 stake);

    /// @notice Emitted when a relayer deposits additional stake
    event StakeAdded(address indexed relayer, uint256 amount);

    /// @notice Emitted when a relayer begins the unbonding process
    event UnstakeInitiated(address indexed relayer, uint256 unlockTime);

    /// @notice Emitted when a relayer withdraws their stake after unbonding
    event StakeWithdrawn(address indexed relayer, uint256 amount);

    /// @notice Emitted when a relayer claims accumulated rewards
    event RewardsClaimed(address indexed relayer, uint256 amount);

    /// @notice Emitted when rewards are added to a relayer's balance
    event RewardAdded(
        address indexed relayer,
        address indexed funder,
        uint256 amount
    );

    /// @notice Emitted when a relayer is slashed for misconduct
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        address recipient
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when registration stake is below MIN_STAKE
    error InsufficientStake(uint256 provided, uint256 required);

    /// @notice Thrown when address is already registered as a relayer
    error AlreadyRegistered(address relayer);

    /// @notice Thrown when action requires registration but address is not registered
    error NotRegistered(address relayer);

    /// @notice Thrown when initiateUnstake is called while already unbonding
    error AlreadyUnbonding(address relayer, uint256 unlockTime);

    /// @notice Thrown when withdrawStake is called before initiating unstake
    error NotUnbonding(address relayer);

    /// @notice Thrown when withdrawStake is called before unbonding period ends
    error StillLocked(uint256 unlockTime, uint256 currentTime);

    /// @notice Thrown when slash amount exceeds relayer's current stake
    error InsufficientStakeForSlash(uint256 stake, uint256 slashAmount);

    /// @notice Thrown when msg.value doesn't match the amount parameter
    error ValueMismatch(uint256 msgValue, uint256 amount);

    /// @notice Thrown when there are no rewards to claim
    error NoRewards(address relayer);

    /// @notice Thrown when an ETH transfer fails
    error TransferFailed(address recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy the registry and grant admin roles
    /// @dev Grants DEFAULT_ADMIN_ROLE, GOVERNANCE_ROLE, and SLASHER_ROLE to deployer
    /// @param _admin Address receiving all initial roles
    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(GOVERNANCE_ROLE, _admin);
        _grantRole(SLASHER_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        REGISTRATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a relayer with initial stake
     * @dev Requires msg.value >= MIN_STAKE (10 ETH). Creates a new RelayerInfo
     *      record and adds the sender to the activeRelayers array. The relayer
     *      starts in ACTIVE state (unlockTime = 0).
     *
     *      Security: ReentrancyGuard prevents re-entrancy during registration.
     *      The msg.value is held as stake until withdrawal after unbonding.
     */
    function register() external payable nonReentrant {
        if (msg.value < MIN_STAKE)
            revert InsufficientStake(msg.value, MIN_STAKE);
        if (relayers[msg.sender].isRegistered)
            revert AlreadyRegistered(msg.sender);

        relayers[msg.sender] = RelayerInfo({
            stake: msg.value,
            rewards: 0,
            unlockTime: 0,
            isRegistered: true
        });

        activeRelayers.push(msg.sender);
        emit RelayerRegistered(msg.sender, msg.value);
    }

    /**
     * @notice Add additional stake to an existing registration
     * @dev Only callable by registered relayers. The additional stake strengthens
     *      the relayer's economic security bond, reducing slash risk exposure.
     */
    function depositStake() external payable nonReentrant {
        if (!relayers[msg.sender].isRegistered)
            revert NotRegistered(msg.sender);
        relayers[msg.sender].stake += msg.value;
        emit StakeAdded(msg.sender, msg.value);
    }

    /*//////////////////////////////////////////////////////////////
                        UNBONDING & WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Begin the unstaking process (7-day unbonding period)
     * @dev Sets unlockTime to block.timestamp + UNBONDING_PERIOD. During the
     *      unbonding period, the relayer should not be selected for relay tasks
     *      (enforced off-chain by checking unlockTime > 0). The relayer can
     *      still be slashed during unbonding.
     *
     *      Cannot be called if already unbonding (unlockTime > 0).
     */
    function initiateUnstake() external {
        if (!relayers[msg.sender].isRegistered)
            revert NotRegistered(msg.sender);
        if (relayers[msg.sender].unlockTime != 0)
            revert AlreadyUnbonding(
                msg.sender,
                relayers[msg.sender].unlockTime
            );

        relayers[msg.sender].unlockTime = block.timestamp + UNBONDING_PERIOD;

        emit UnstakeInitiated(msg.sender, relayers[msg.sender].unlockTime);
    }

    /**
     * @notice Withdraw stake after the unbonding period has elapsed
     * @dev Follows the Checks-Effects-Interactions (CEI) pattern:
     *      1. Checks: Verify unbonding started and period elapsed
     *      2. Effects: Zero out stake, unregister, clear unlock time
     *      3. Interactions: Transfer ETH to caller
     *
     *      Security: ReentrancyGuard + CEI prevents re-entrancy attacks.
     *      The full stake is returned; partial withdrawal is not supported.
     */
    function withdrawStake() external nonReentrant {
        RelayerInfo storage info = relayers[msg.sender];
        if (info.unlockTime == 0) revert NotUnbonding(msg.sender);
        if (block.timestamp < info.unlockTime)
            revert StillLocked(info.unlockTime, block.timestamp);

        uint256 amount = info.stake;
        info.stake = 0;
        info.isRegistered = false;
        info.unlockTime = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed(msg.sender, amount);

        emit StakeWithdrawn(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           SLASHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Slash a relayer for misconduct (e.g., invalid relays, censorship)
     * @dev Only callable by SLASHER_ROLE (governance/security module). Transfers
     *      slashed funds to a recipient (could be insurance fund, reporter, or treasury).
     *
     *      Security: Cannot slash more than current stake (prevents underflow).
     *      Slashing can occur during unbonding — this is by design to prevent
     *      "slash-and-run" attacks.
     * @param _relayer Address of the relayer to slash
     * @param _amount Amount of stake to confiscate
     * @param _recipient Address to receive the slashed funds
     */
    function slash(
        address _relayer,
        uint256 _amount,
        address _recipient
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        RelayerInfo storage info = relayers[_relayer];
        if (info.stake < _amount)
            revert InsufficientStakeForSlash(info.stake, _amount);

        info.stake -= _amount;

        (bool success, ) = _recipient.call{value: _amount}("");
        if (!success) revert TransferFailed(_recipient, _amount);

        emit RelayerSlashed(_relayer, _amount, _recipient);
    }

    /*//////////////////////////////////////////////////////////////
                           REWARDS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add rewards to a relayer's balance
     * @dev Anyone can fund rewards (protocol fees, tip distribution, etc.).
     *      The msg.value must exactly match the _amount parameter to prevent
     *      accounting mismatches. Rewards accumulate until claimed.
     * @param _relayer Relayer to receive the reward
     * @param _amount Amount of ETH reward (must equal msg.value)
     */
    function addReward(address _relayer, uint256 _amount) external payable {
        if (msg.value != _amount) revert ValueMismatch(msg.value, _amount);
        if (!relayers[_relayer].isRegistered) revert NotRegistered(_relayer);

        relayers[_relayer].rewards += _amount;
        emit RewardAdded(_relayer, msg.sender, _amount);
    }

    /**
     * @notice Claim accumulated rewards
     * @dev Follows CEI pattern: zeros rewards before transfer. Only the relayer
     *      themselves can claim their rewards. Reverts if no rewards available
     *      to prevent wasted gas.
     *
     *      Security: ReentrancyGuard prevents re-entrancy during ETH transfer.
     */
    function claimRewards() external nonReentrant {
        uint256 amount = relayers[msg.sender].rewards;
        if (amount == 0) revert NoRewards(msg.sender);

        relayers[msg.sender].rewards = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed(msg.sender, amount);

        emit RewardsClaimed(msg.sender, amount);
    }
}
