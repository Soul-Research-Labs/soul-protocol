// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PILStaking
 * @notice Staking contract for PIL token holders and relayers
 * @dev Supports multiple staking pools with different lock periods and rewards
 *
 * Staking Tiers:
 * - Flexible: No lock, 5% APY
 * - Bronze (30 days): 8% APY
 * - Silver (90 days): 12% APY
 * - Gold (180 days): 18% APY
 * - Platinum (365 days): 25% APY
 *
 * Relayer Requirements:
 * - Minimum stake: 50,000 PIL
 * - Slashing for malicious behavior
 * - Priority in transaction processing
 */
contract PILStaking is ReentrancyGuard, AccessControl, Pausable {
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant REWARDS_MANAGER = keccak256("REWARDS_MANAGER");

    // Staking token
    IERC20 public immutable pilToken;

    // Staking tiers
    enum StakingTier {
        FLEXIBLE, // No lock
        BRONZE, // 30 days
        SILVER, // 90 days
        GOLD, // 180 days
        PLATINUM // 365 days
    }

    struct TierConfig {
        uint256 lockDuration;
        uint256 rewardRate; // APY in basis points (10000 = 100%)
        uint256 minStake;
    }

    struct Stake {
        uint256 amount;
        uint256 startTime;
        uint256 endTime;
        StakingTier tier;
        uint256 rewardDebt;
        bool isRelayer;
    }

    struct Relayer {
        bool isActive;
        uint256 stakedAmount;
        uint256 totalProcessed;
        uint256 successCount;
        uint256 slashCount;
        uint256 reputation;
    }

    // Storage
    mapping(StakingTier => TierConfig) public tierConfigs;
    mapping(address => Stake[]) public userStakes;
    mapping(address => Relayer) public relayers;
    address[] public activeRelayers;

    // Rewards tracking
    uint256 public totalStaked;
    uint256 public rewardsPool;
    uint256 public accRewardPerShare;
    uint256 public lastRewardTime;

    // Relayer settings
    uint256 public constant MIN_RELAYER_STAKE = 50_000 * 10 ** 18;
    uint256 public constant SLASH_PERCENTAGE = 1000; // 10%
    uint256 public constant MAX_SLASHES = 3;

    // Events
    event Staked(
        address indexed user,
        uint256 amount,
        StakingTier tier,
        uint256 stakeIndex
    );
    event Unstaked(address indexed user, uint256 amount, uint256 stakeIndex);
    event RewardsClaimed(address indexed user, uint256 amount);
    event RelayerRegistered(address indexed relayer);
    event RelayerDeactivated(address indexed relayer);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        string reason
    );
    event RewardsAdded(uint256 amount);

    constructor(address _pilToken) {
        pilToken = IERC20(_pilToken);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SLASHER_ROLE, msg.sender);
        _grantRole(REWARDS_MANAGER, msg.sender);

        // Initialize tier configs
        tierConfigs[StakingTier.FLEXIBLE] = TierConfig({
            lockDuration: 0,
            rewardRate: 500, // 5% APY
            minStake: 100 * 10 ** 18
        });
        tierConfigs[StakingTier.BRONZE] = TierConfig({
            lockDuration: 30 days,
            rewardRate: 800, // 8% APY
            minStake: 1_000 * 10 ** 18
        });
        tierConfigs[StakingTier.SILVER] = TierConfig({
            lockDuration: 90 days,
            rewardRate: 1200, // 12% APY
            minStake: 5_000 * 10 ** 18
        });
        tierConfigs[StakingTier.GOLD] = TierConfig({
            lockDuration: 180 days,
            rewardRate: 1800, // 18% APY
            minStake: 25_000 * 10 ** 18
        });
        tierConfigs[StakingTier.PLATINUM] = TierConfig({
            lockDuration: 365 days,
            rewardRate: 2500, // 25% APY
            minStake: 100_000 * 10 ** 18
        });

        lastRewardTime = block.timestamp;
    }

    /**
     * @notice Stake PIL tokens
     * @param amount Amount to stake
     * @param tier Staking tier
     */
    function stake(
        uint256 amount,
        StakingTier tier
    ) external nonReentrant whenNotPaused {
        TierConfig memory config = tierConfigs[tier];
        require(amount >= config.minStake, "Below minimum stake");

        _updateRewards();

        // Transfer tokens
        pilToken.safeTransferFrom(msg.sender, address(this), amount);

        // Create stake
        uint256 endTime = config.lockDuration > 0
            ? block.timestamp + config.lockDuration
            : 0;

        userStakes[msg.sender].push(
            Stake({
                amount: amount,
                startTime: block.timestamp,
                endTime: endTime,
                tier: tier,
                rewardDebt: (amount * accRewardPerShare) / 1e18,
                isRelayer: false
            })
        );

        totalStaked += amount;

        emit Staked(
            msg.sender,
            amount,
            tier,
            userStakes[msg.sender].length - 1
        );
    }

    /**
     * @notice Unstake PIL tokens
     * @param stakeIndex Index of stake to unstake
     */
    function unstake(uint256 stakeIndex) external nonReentrant {
        require(
            stakeIndex < userStakes[msg.sender].length,
            "Invalid stake index"
        );

        Stake storage userStake = userStakes[msg.sender][stakeIndex];
        require(userStake.amount > 0, "Already unstaked");
        require(
            userStake.endTime == 0 || block.timestamp >= userStake.endTime,
            "Still locked"
        );

        // Check relayer requirements
        if (userStake.isRelayer) {
            require(
                _getTotalUserStake(msg.sender) - userStake.amount >=
                    MIN_RELAYER_STAKE ||
                    !relayers[msg.sender].isActive,
                "Relayer minimum stake required"
            );
        }

        _updateRewards();

        // Calculate and transfer rewards
        uint256 pending = _pendingRewards(userStake);
        uint256 total = userStake.amount + pending;

        // Update state
        totalStaked -= userStake.amount;
        userStake.amount = 0;

        // Transfer
        if (pending > 0 && rewardsPool >= pending) {
            rewardsPool -= pending;
        }
        pilToken.safeTransfer(msg.sender, total);

        emit Unstaked(msg.sender, total, stakeIndex);
    }

    /**
     * @notice Claim pending rewards without unstaking
     */
    function claimRewards() external nonReentrant {
        _updateRewards();

        uint256 totalPending = 0;
        Stake[] storage stakes = userStakes[msg.sender];

        for (uint256 i = 0; i < stakes.length; i++) {
            if (stakes[i].amount > 0) {
                uint256 pending = _pendingRewards(stakes[i]);
                totalPending += pending;
                stakes[i].rewardDebt =
                    (stakes[i].amount * accRewardPerShare) /
                    1e18;
            }
        }

        require(totalPending > 0, "No rewards to claim");
        require(rewardsPool >= totalPending, "Insufficient rewards pool");

        rewardsPool -= totalPending;
        pilToken.safeTransfer(msg.sender, totalPending);

        emit RewardsClaimed(msg.sender, totalPending);
    }

    /**
     * @notice Register as a relayer
     */
    function registerRelayer() external nonReentrant {
        require(
            _getTotalUserStake(msg.sender) >= MIN_RELAYER_STAKE,
            "Insufficient stake"
        );
        require(!relayers[msg.sender].isActive, "Already a relayer");

        relayers[msg.sender] = Relayer({
            isActive: true,
            stakedAmount: _getTotalUserStake(msg.sender),
            totalProcessed: 0,
            successCount: 0,
            slashCount: 0,
            reputation: 100
        });

        activeRelayers.push(msg.sender);

        // Mark stakes as relayer stakes
        Stake[] storage stakes = userStakes[msg.sender];
        for (uint256 i = 0; i < stakes.length; i++) {
            if (stakes[i].amount > 0) {
                stakes[i].isRelayer = true;
            }
        }

        emit RelayerRegistered(msg.sender);
    }

    /**
     * @notice Deactivate relayer status
     */
    function deactivateRelayer() external {
        require(relayers[msg.sender].isActive, "Not an active relayer");

        relayers[msg.sender].isActive = false;
        _removeFromActiveRelayers(msg.sender);

        // Unmark relayer stakes
        Stake[] storage stakes = userStakes[msg.sender];
        for (uint256 i = 0; i < stakes.length; i++) {
            stakes[i].isRelayer = false;
        }

        emit RelayerDeactivated(msg.sender);
    }

    /**
     * @notice Slash a relayer for malicious behavior
     * @param relayer Relayer address
     * @param reason Reason for slashing
     */
    function slashRelayer(
        address relayer,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) {
        require(relayers[relayer].isActive, "Not an active relayer");

        Relayer storage rel = relayers[relayer];
        uint256 slashAmount = (rel.stakedAmount * SLASH_PERCENTAGE) / 10000;

        // Apply slash to stakes
        Stake[] storage stakes = userStakes[relayer];
        uint256 remaining = slashAmount;

        for (uint256 i = 0; i < stakes.length && remaining > 0; i++) {
            if (stakes[i].amount > 0 && stakes[i].isRelayer) {
                uint256 slash = stakes[i].amount > remaining
                    ? remaining
                    : stakes[i].amount;
                stakes[i].amount -= slash;
                totalStaked -= slash;
                remaining -= slash;
            }
        }

        // Update relayer stats
        rel.slashCount++;
        rel.reputation = rel.reputation > 20 ? rel.reputation - 20 : 0;
        rel.stakedAmount -= slashAmount;

        // Deactivate if too many slashes
        if (rel.slashCount >= MAX_SLASHES) {
            rel.isActive = false;
            _removeFromActiveRelayers(relayer);
        }

        // Add slashed tokens to rewards pool
        rewardsPool += slashAmount;

        emit RelayerSlashed(relayer, slashAmount, reason);
    }

    /**
     * @notice Record successful relay operation
     * @param relayer Relayer address
     */
    function recordRelaySuccess(
        address relayer
    ) external onlyRole(SLASHER_ROLE) {
        Relayer storage rel = relayers[relayer];
        if (rel.isActive) {
            rel.totalProcessed++;
            rel.successCount++;
            if (rel.reputation < 100) {
                rel.reputation += 1;
            }
        }
    }

    /**
     * @notice Add rewards to the pool
     * @param amount Amount of rewards to add
     */
    function addRewards(uint256 amount) external onlyRole(REWARDS_MANAGER) {
        pilToken.safeTransferFrom(msg.sender, address(this), amount);
        rewardsPool += amount;
        emit RewardsAdded(amount);
    }

    // View functions

    /**
     * @notice Get user's total staked amount
     */
    function getUserTotalStake(address user) external view returns (uint256) {
        return _getTotalUserStake(user);
    }

    /**
     * @notice Get user's pending rewards
     */
    function getUserPendingRewards(
        address user
    ) external view returns (uint256) {
        uint256 total = 0;
        Stake[] storage stakes = userStakes[user];

        for (uint256 i = 0; i < stakes.length; i++) {
            if (stakes[i].amount > 0) {
                total += _pendingRewards(stakes[i]);
            }
        }
        return total;
    }

    /**
     * @notice Get user's stakes
     */
    function getUserStakes(
        address user
    ) external view returns (Stake[] memory) {
        return userStakes[user];
    }

    /**
     * @notice Get active relayers
     */
    function getActiveRelayers() external view returns (address[] memory) {
        return activeRelayers;
    }

    /**
     * @notice Get relayer info
     */
    function getRelayerInfo(
        address relayer
    ) external view returns (Relayer memory) {
        return relayers[relayer];
    }

    // Internal functions

    function _updateRewards() internal {
        if (totalStaked == 0) {
            lastRewardTime = block.timestamp;
            return;
        }

        uint256 elapsed = block.timestamp - lastRewardTime;
        if (elapsed > 0 && rewardsPool > 0) {
            // Simple reward distribution based on time
            uint256 reward = (rewardsPool * elapsed) / (365 days);
            if (reward > rewardsPool) {
                reward = rewardsPool;
            }
            accRewardPerShare += (reward * 1e18) / totalStaked;
            lastRewardTime = block.timestamp;
        }
    }

    function _pendingRewards(
        Stake storage userStake
    ) internal view returns (uint256) {
        uint256 elapsed = block.timestamp - userStake.startTime;
        TierConfig memory config = tierConfigs[userStake.tier];

        // Calculate tier-specific rewards
        uint256 annualReward = (userStake.amount * config.rewardRate) / 10000;
        uint256 pending = (annualReward * elapsed) / 365 days;

        // Cap at rewards pool
        return pending > rewardsPool ? rewardsPool : pending;
    }

    function _getTotalUserStake(address user) internal view returns (uint256) {
        uint256 total = 0;
        Stake[] storage stakes = userStakes[user];

        for (uint256 i = 0; i < stakes.length; i++) {
            total += stakes[i].amount;
        }
        return total;
    }

    function _removeFromActiveRelayers(address relayer) internal {
        for (uint256 i = 0; i < activeRelayers.length; i++) {
            if (activeRelayers[i] == relayer) {
                activeRelayers[i] = activeRelayers[activeRelayers.length - 1];
                activeRelayers.pop();
                break;
            }
        }
    }

    // Admin functions

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function updateTierConfig(
        StakingTier tier,
        uint256 lockDuration,
        uint256 rewardRate,
        uint256 minStake
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        tierConfigs[tier] = TierConfig({
            lockDuration: lockDuration,
            rewardRate: rewardRate,
            minStake: minStake
        });
    }
}
