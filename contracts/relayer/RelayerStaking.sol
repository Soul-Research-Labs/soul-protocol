// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title RelayerStaking
 * @author ZASEON
 * @notice Staking and slashing mechanism for Zaseon relayers
 * @custom:security-contact security@zaseonprotocol.io
 * @dev Relayers must stake tokens to participate in the network
 */
contract RelayerStaking is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    error InvalidAmount();
    error InsufficientStake();
    error PendingUnstakeExists();
    error NoPendingUnstake();
    error UnbondingPeriodNotComplete();
    error NoStakeFound();
    error NoStakers();
    error InvalidSlashingPercentage();

    // Staking token (Zaseon token)
    IERC20 public immutable stakingToken;

    // Minimum stake required to be an active relayer
    uint256 public minStake;

    // Unbonding period (7 days)
    uint256 public constant UNBONDING_PERIOD = 7 days;

    // Slashing percentage (in basis points, 1000 = 10%)
    uint256 public slashingPercentage = 1000;

    // Relayer information
    struct Relayer {
        uint256 stakedAmount;
        uint256 pendingUnstake;
        uint256 unstakeRequestTime;
        uint256 rewardDebt;
        uint256 successfulRelays;
        uint256 failedRelays;
        bool isActive;
        string metadata; // IPFS hash or URL for relayer info
    }

    // Relayer address => Relayer info
    mapping(address => Relayer) public relayers;

    // List of active relayers
    address[] public activeRelayers;
    mapping(address => uint256) public relayerIndex;

    // Total staked across all relayers
    uint256 public totalStaked;

    // Reward pool
    uint256 public rewardPool;
    uint256 public rewardPerShare;
    uint256 public constant PRECISION = 1e18;

    // Flash loan protection: minimum stake duration before rewards accrue
    uint256 public constant MIN_STAKE_DURATION = 1 days;
    mapping(address => uint256) public stakingTimestamp;

    // Events
    /// @notice Emitted when a relayer stakes tokens
    /// @param relayer The relayer address
    /// @param amount The amount of tokens staked
    event Staked(address indexed relayer, uint256 amount);
    /// @notice Emitted when a relayer requests to unstake tokens
    /// @param relayer The relayer address
    /// @param amount The amount of tokens requested for unstaking
    event UnstakeRequested(address indexed relayer, uint256 amount);
    /// @notice Emitted when tokens are withdrawn after the unbonding period
    /// @param relayer The relayer address
    /// @param amount The amount of tokens unstaked
    event Unstaked(address indexed relayer, uint256 amount);
    /// @notice Emitted when a relayer's stake is slashed for misbehavior
    /// @param relayer The slashed relayer address
    /// @param amount The amount of tokens slashed
    /// @param reason The reason for the slashing
    event Slashed(address indexed relayer, uint256 amount, string reason);
    /// @notice Emitted when a relayer becomes active (meets minimum stake)
    /// @param relayer The activated relayer address
    event RelayerActivated(address indexed relayer);
    /// @notice Emitted when a relayer is deactivated
    /// @param relayer The deactivated relayer address
    event RelayerDeactivated(address indexed relayer);
    /// @notice Emitted when a relayer claims accrued rewards
    /// @param relayer The relayer address
    /// @param amount The amount of rewards claimed
    event RewardClaimed(address indexed relayer, uint256 amount);
    /// @notice Emitted when new rewards are added to the reward pool
    /// @param amount The amount of rewards added
    event RewardAdded(uint256 amount);

    constructor(address _stakingToken, uint256 _minStake, address admin) {
        stakingToken = IERC20(_stakingToken);
        minStake = _minStake;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);
    }

    /**
     * @notice Stake tokens to become a relayer
     * @param amount Amount to stake
     */
    function stake(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount();

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);

        Relayer storage relayer = relayers[msg.sender];

        // Claim pending rewards first (only if eligible)
        if (
            relayer.stakedAmount > 0 &&
            block.timestamp >= stakingTimestamp[msg.sender] + MIN_STAKE_DURATION
        ) {
            _claimRewards(msg.sender);
        }

        // Update staking timestamp for flash loan protection
        if (relayer.stakedAmount == 0) {
            stakingTimestamp[msg.sender] = block.timestamp;
        }

        relayer.stakedAmount += amount;
        relayer.rewardDebt =
            (relayer.stakedAmount * rewardPerShare) /
            PRECISION;
        totalStaked += amount;

        emit Staked(msg.sender, amount);

        // Activate if meets minimum stake
        if (!relayer.isActive && relayer.stakedAmount >= minStake) {
            _activateRelayer(msg.sender);
        }
    }

    /**
     * @notice Request to unstake tokens (starts unbonding period)
     * @param amount Amount to unstake
     */
    function requestUnstake(uint256 amount) external nonReentrant {
        Relayer storage relayer = relayers[msg.sender];
        if (relayer.stakedAmount < amount) revert InsufficientStake();
        if (relayer.pendingUnstake != 0) revert PendingUnstakeExists();

        // Claim pending rewards first
        _claimRewards(msg.sender);

        relayer.stakedAmount -= amount;
        relayer.pendingUnstake = amount;
        relayer.unstakeRequestTime = block.timestamp;
        relayer.rewardDebt =
            (relayer.stakedAmount * rewardPerShare) /
            PRECISION;
        totalStaked -= amount;

        emit UnstakeRequested(msg.sender, amount);

        // Deactivate if below minimum
        if (relayer.isActive && relayer.stakedAmount < minStake) {
            _deactivateRelayer(msg.sender);
        }
    }

    /**
     * @notice Complete unstaking after unbonding period
     */
    function completeUnstake() external nonReentrant {
        Relayer storage relayer = relayers[msg.sender];
        if (relayer.pendingUnstake == 0) revert NoPendingUnstake();
        if (block.timestamp < relayer.unstakeRequestTime + UNBONDING_PERIOD)
            revert UnbondingPeriodNotComplete();

        uint256 amount = relayer.pendingUnstake;
        relayer.pendingUnstake = 0;
        relayer.unstakeRequestTime = 0;

        stakingToken.safeTransfer(msg.sender, amount);

        emit Unstaked(msg.sender, amount);
    }

    /**
     * @notice Slash a relayer for misbehavior
     * @param relayerAddress Address of the relayer to slash
     * @param reason Reason for slashing
     */
    function slash(
        address relayerAddress,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        Relayer storage relayer = relayers[relayerAddress];
        if (relayer.stakedAmount == 0) revert NoStakeFound();

        // SECURITY FIX H-7: Update reward debt BEFORE modifying stakedAmount
        // This prevents the slashed relayer from earning rewards on their own slashed tokens
        relayer.rewardDebt =
            (relayer.stakedAmount * rewardPerShare) /
            PRECISION;

        uint256 slashAmount = (relayer.stakedAmount * slashingPercentage) /
            10000;
        relayer.stakedAmount -= slashAmount;
        relayer.failedRelays++;
        totalStaked -= slashAmount;

        // Add slashed tokens to reward pool
        rewardPool += slashAmount;
        if (totalStaked > 0) {
            rewardPerShare += (slashAmount * PRECISION) / totalStaked;
        }

        emit Slashed(relayerAddress, slashAmount, reason);

        // Deactivate if below minimum
        if (relayer.isActive && relayer.stakedAmount < minStake) {
            _deactivateRelayer(relayerAddress);
        }
    }

    /**
     * @notice Record a successful relay
     * @param relayerAddress Address of the relayer
     */
    function recordSuccessfulRelay(
        address relayerAddress
    ) external onlyRole(ADMIN_ROLE) {
        relayers[relayerAddress].successfulRelays++;
    }

    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external nonReentrant {
        _claimRewards(msg.sender);
    }

    /**
     * @notice Add rewards to the pool
     * @param amount Amount of tokens to add
     */
    function addRewards(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount();
        if (totalStaked == 0) revert NoStakers();

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);

        rewardPool += amount;
        rewardPerShare += (amount * PRECISION) / totalStaked;

        emit RewardAdded(amount);
    }

    /**
     * @dev Internal function to claim rewards
     * @notice Includes flash loan protection - minimum stake duration required
     */
    function _claimRewards(address relayerAddress) internal {
        Relayer storage relayer = relayers[relayerAddress];

        // Flash loan protection: require minimum stake duration
        if (
            block.timestamp <
            stakingTimestamp[relayerAddress] + MIN_STAKE_DURATION
        ) {
            return; // Silently return if stake is too new
        }

        uint256 pending = ((relayer.stakedAmount * rewardPerShare) / PRECISION);
        // SECURITY FIX H-7: Prevent underflow when rewardDebt exceeds current share
        pending = pending > relayer.rewardDebt
            ? pending - relayer.rewardDebt
            : 0;

        if (pending > 0) {
            relayer.rewardDebt =
                (relayer.stakedAmount * rewardPerShare) /
                PRECISION;
            stakingToken.safeTransfer(relayerAddress, pending);
            emit RewardClaimed(relayerAddress, pending);
        }
    }

    /**
     * @dev Activate a relayer
     */
    function _activateRelayer(address relayerAddress) internal {
        Relayer storage relayer = relayers[relayerAddress];
        relayer.isActive = true;
        relayerIndex[relayerAddress] = activeRelayers.length;
        activeRelayers.push(relayerAddress);
        emit RelayerActivated(relayerAddress);
    }

    /**
     * @dev Deactivate a relayer
     */
    function _deactivateRelayer(address relayerAddress) internal {
        Relayer storage relayer = relayers[relayerAddress];
        relayer.isActive = false;

        // Remove from active list
        uint256 index = relayerIndex[relayerAddress];
        uint256 lastIndex = activeRelayers.length - 1;

        if (index != lastIndex) {
            address lastRelayer = activeRelayers[lastIndex];
            activeRelayers[index] = lastRelayer;
            relayerIndex[lastRelayer] = index;
        }

        activeRelayers.pop();
        delete relayerIndex[relayerAddress];

        emit RelayerDeactivated(relayerAddress);
    }

    /**
     * @notice Get pending rewards for a relayer
     * @param relayerAddress The relayer address to query
     * @return The amount of unclaimed rewards
     */
    function pendingRewards(
        address relayerAddress
    ) external view returns (uint256) {
        Relayer storage relayer = relayers[relayerAddress];
        uint256 computed = (relayer.stakedAmount * rewardPerShare) / PRECISION;
        // SECURITY FIX H-7: Prevent underflow in pending rewards view
        return
            computed > relayer.rewardDebt ? computed - relayer.rewardDebt : 0;
    }

    /**
     * @notice Get all active relayers
     * @return Array of active relayer addresses
     */
    function getActiveRelayers() external view returns (address[] memory) {
        return activeRelayers;
    }

    /**
     * @notice Get relayer count
     * @return The number of currently active relayers
     */
    function getActiveRelayerCount() external view returns (uint256) {
        return activeRelayers.length;
    }

    /**
     * @notice Check if address is an active relayer
     * @param relayerAddress The address to check
     * @return True if the address is an active relayer
     */
    function isActiveRelayer(
        address relayerAddress
    ) external view returns (bool) {
        return relayers[relayerAddress].isActive;
    }

    /**
     * @notice Update minimum stake requirement
     * @param _minStake The new minimum stake amount in wei
     */
    function setMinStake(uint256 _minStake) external onlyRole(ADMIN_ROLE) {
        minStake = _minStake;
    }

    /**
     * @notice Update slashing percentage
     * @param _slashingPercentage The new slashing percentage in basis points (max 5000 = 50%)
     */
    function setSlashingPercentage(
        uint256 _slashingPercentage
    ) external onlyRole(ADMIN_ROLE) {
        if (_slashingPercentage > 5000) revert InvalidSlashingPercentage();
        slashingPercentage = _slashingPercentage;
    }

    /**
     * @notice Update relayer metadata
     * @param metadata The new metadata string (e.g. endpoint URL, name)
     */
    function updateMetadata(string calldata metadata) external {
        relayers[msg.sender].metadata = metadata;
    }
}
