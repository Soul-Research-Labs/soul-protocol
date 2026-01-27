// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title RelayerStaking
 * @notice Staking and slashing mechanism for Soul relayers
 * @dev Relayers must stake tokens to participate in the network
 */
contract RelayerStaking is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // Staking token (Soul token)
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
    event Staked(address indexed relayer, uint256 amount);
    event UnstakeRequested(address indexed relayer, uint256 amount);
    event Unstaked(address indexed relayer, uint256 amount);
    event Slashed(address indexed relayer, uint256 amount, string reason);
    event RelayerActivated(address indexed relayer);
    event RelayerDeactivated(address indexed relayer);
    event RewardClaimed(address indexed relayer, uint256 amount);
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
        require(amount > 0, "Cannot stake 0");

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
        require(relayer.stakedAmount >= amount, "Insufficient stake");
        require(relayer.pendingUnstake == 0, "Pending unstake exists");

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
        require(relayer.pendingUnstake > 0, "No pending unstake");
        require(
            block.timestamp >= relayer.unstakeRequestTime + UNBONDING_PERIOD,
            "Unbonding period not complete"
        );

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
        require(relayer.stakedAmount > 0, "Relayer has no stake");

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
        require(amount > 0, "Cannot add 0");
        require(totalStaked > 0, "No stakers");

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

        uint256 pending = ((relayer.stakedAmount * rewardPerShare) /
            PRECISION) - relayer.rewardDebt;

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
     */
    function pendingRewards(
        address relayerAddress
    ) external view returns (uint256) {
        Relayer storage relayer = relayers[relayerAddress];
        return
            ((relayer.stakedAmount * rewardPerShare) / PRECISION) -
            relayer.rewardDebt;
    }

    /**
     * @notice Get all active relayers
     */
    function getActiveRelayers() external view returns (address[] memory) {
        return activeRelayers;
    }

    /**
     * @notice Get relayer count
     */
    function getActiveRelayerCount() external view returns (uint256) {
        return activeRelayers.length;
    }

    /**
     * @notice Check if address is an active relayer
     */
    function isActiveRelayer(
        address relayerAddress
    ) external view returns (bool) {
        return relayers[relayerAddress].isActive;
    }

    /**
     * @notice Update minimum stake requirement
     */
    function setMinStake(uint256 _minStake) external onlyRole(ADMIN_ROLE) {
        minStake = _minStake;
    }

    /**
     * @notice Update slashing percentage
     */
    function setSlashingPercentage(
        uint256 _slashingPercentage
    ) external onlyRole(ADMIN_ROLE) {
        require(_slashingPercentage <= 5000, "Max 50%");
        slashingPercentage = _slashingPercentage;
    }

    /**
     * @notice Update relayer metadata
     */
    function updateMetadata(string calldata metadata) external {
        relayers[msg.sender].metadata = metadata;
    }
}
