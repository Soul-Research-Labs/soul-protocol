// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title InstantRelayerRewards
 * @author Soul Protocol
 * @notice Per-relay instant fee distribution with speed-based tiers
 * @dev Layered on top of existing RelayerStaking pool-share model.
 *      RelayerStaking handles long-term staking rewards; this contract handles
 *      instant per-relay payouts tied to speed of fulfillment.
 *
 * REWARD TIERS:
 *   < 30 seconds  → 1.5x base reward
 *   < 60 seconds  → 1.25x base reward
 *   < 5 minutes   → 1.0x base reward
 *   >= 5 minutes  → 0.9x base reward (penalty for slowness)
 *
 * FLOW:
 *   1. Fee deposited via depositRelayFee() when relay request is created
 *   2. Relay completes → completeRelayWithReward() calculates tiered payout
 *   3. Protocol takes cut, relayer gets instant reward, surplus refunded
 *
 * SECURITY:
 * - All state-changing externals are nonReentrant
 * - Only authorized contracts can deposit/complete
 * - Zero-address validation on all critical params
 * - Bounded reward multiplier prevents overflow
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract InstantRelayerRewards is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("RELAY_MANAGER_ROLE") — authorized to record relay completions
    bytes32 public constant RELAY_MANAGER_ROLE =
        keccak256("RELAY_MANAGER_ROLE");

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Speed tier thresholds
    uint256 public constant TIER_ULTRA_FAST = 30 seconds;
    uint256 public constant TIER_FAST = 60 seconds;
    uint256 public constant TIER_NORMAL = 5 minutes;

    /// @notice Reward multipliers in basis points (10000 = 1x)
    uint256 public constant MULTIPLIER_ULTRA_FAST = 15000; // 1.5x
    uint256 public constant MULTIPLIER_FAST = 12500; // 1.25x
    uint256 public constant MULTIPLIER_NORMAL = 10000; // 1.0x
    uint256 public constant MULTIPLIER_SLOW = 9000; // 0.9x

    /// @notice Protocol fee in basis points (5%)
    uint256 public constant PROTOCOL_FEE_BPS = 500;

    /// @notice Basis points denominator
    uint256 private constant BPS = 10_000;

    /// @notice Maximum relays tracked per relayer for stats (gas bound)
    uint256 public constant MAX_HISTORY_PER_RELAYER = 1000;

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Speed tier classification
    enum SpeedTier {
        ULTRA_FAST, // < 30s
        FAST, // < 60s
        NORMAL, // < 5min
        SLOW // >= 5min
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A relay fee deposit awaiting completion
    struct RelayDeposit {
        address requester; // Who deposited the fee
        address relayer; // Assigned relayer (set on claim)
        uint256 baseReward; // Base reward amount
        uint48 depositedAt; // When fee was deposited
        uint48 claimedAt; // When relayer claimed
        bool completed; // Whether relay is done
        bool refunded; // Whether excess was refunded
    }

    /// @notice Aggregate stats for a relayer
    struct RelayerStats {
        uint256 totalRewards; // Total instant rewards earned
        uint256 totalRelays; // Total relays completed
        uint256 ultraFastCount; // Number of ultra-fast relays
        uint256 fastCount; // Number of fast relays
        uint256 normalCount; // Number of normal relays
        uint256 slowCount; // Number of slow relays
        uint256 avgResponseTime; // Weighted average response time (seconds)
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Relay deposits (relayId => deposit)
    mapping(bytes32 => RelayDeposit) public deposits;

    /// @notice Per-relayer aggregate statistics
    mapping(address => RelayerStats) public relayerStats;

    /// @notice Accumulated protocol fees
    uint256 public protocolFees;

    /// @notice Total rewards distributed
    uint256 public totalRewardsDistributed;

    /// @notice Total relays completed through this contract
    uint256 public totalRelaysCompleted;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RelayFeeDeposited(
        bytes32 indexed relayId,
        address indexed requester,
        uint256 baseReward
    );

    event RelayClaimed(bytes32 indexed relayId, address indexed relayer);

    event RelayRewardPaid(
        bytes32 indexed relayId,
        address indexed relayer,
        uint256 reward,
        SpeedTier tier,
        uint256 responseTime
    );

    event ProtocolFeesWithdrawn(address indexed to, uint256 amount);

    event ExcessRefunded(
        bytes32 indexed relayId,
        address indexed requester,
        uint256 amount
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidAmount();
    error DepositNotFound();
    error DepositAlreadyCompleted();
    error DepositAlreadyRefunded();
    error RelayNotClaimed();
    error NotAssignedRelayer();
    error NoFeesToWithdraw();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Admin address (DEFAULT_ADMIN_ROLE)
    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(RELAY_MANAGER_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                         RELAY FEE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit a relay fee for a given relay request
    /// @param relayId Unique relay identifier
    /// @param requester The user who is paying for the relay
    /// @dev Called by the fee market or intent layer when a relay request is created
    function depositRelayFee(
        bytes32 relayId,
        address requester
    ) external payable nonReentrant onlyRole(RELAY_MANAGER_ROLE) {
        if (requester == address(0)) revert ZeroAddress();
        if (msg.value == 0) revert InvalidAmount();

        deposits[relayId] = RelayDeposit({
            requester: requester,
            relayer: address(0),
            baseReward: msg.value,
            depositedAt: uint48(block.timestamp),
            claimedAt: 0,
            completed: false,
            refunded: false
        });

        emit RelayFeeDeposited(relayId, requester, msg.value);
    }

    /// @notice Record that a relayer has claimed a relay
    /// @param relayId The relay being claimed
    /// @param relayer The relayer claiming it
    function claimRelay(
        bytes32 relayId,
        address relayer
    ) external nonReentrant onlyRole(RELAY_MANAGER_ROLE) {
        if (relayer == address(0)) revert ZeroAddress();
        RelayDeposit storage deposit = deposits[relayId];
        if (deposit.requester == address(0)) revert DepositNotFound();
        if (deposit.completed) revert DepositAlreadyCompleted();

        deposit.relayer = relayer;
        deposit.claimedAt = uint48(block.timestamp);

        emit RelayClaimed(relayId, relayer);
    }

    /// @notice Complete a relay and pay the instant reward
    /// @param relayId The completed relay
    /// @dev Only callable by RELAY_MANAGER_ROLE. Calculates speed tier and pays tiered reward.
    function completeRelayWithReward(
        bytes32 relayId
    ) external nonReentrant onlyRole(RELAY_MANAGER_ROLE) {
        RelayDeposit storage deposit = deposits[relayId];
        if (deposit.requester == address(0)) revert DepositNotFound();
        if (deposit.completed) revert DepositAlreadyCompleted();
        if (deposit.relayer == address(0)) revert RelayNotClaimed();

        deposit.completed = true;

        // Calculate response time
        uint256 responseTime;
        if (deposit.claimedAt > 0) {
            responseTime = block.timestamp - uint256(deposit.claimedAt);
        }

        // Determine speed tier and multiplier
        (SpeedTier tier, uint256 multiplier) = _getSpeedTier(responseTime);

        // Calculate tiered reward:
        // The deposit (baseReward) funds the maximum possible payout (ULTRA_FAST = 1.5x).
        // For slower tiers, reward < deposit → surplus refunded to requester.
        // Formula: reward = deposit * multiplier / MULTIPLIER_ULTRA_FAST
        // This ensures ULTRA_FAST gets full deposit, FAST gets 83.3%, NORMAL 66.7%, SLOW 60%.
        uint256 tieredReward = (deposit.baseReward * multiplier) /
            MULTIPLIER_ULTRA_FAST;

        // Protocol cut from the tiered reward
        uint256 protocolCut = (tieredReward * PROTOCOL_FEE_BPS) / BPS;
        uint256 relayerPayout = tieredReward - protocolCut;

        // Surplus returned to requester (slower tiers don't use full deposit)
        uint256 surplus = deposit.baseReward - tieredReward;

        protocolFees += protocolCut;
        totalRewardsDistributed += relayerPayout;

        unchecked {
            ++totalRelaysCompleted;
        }

        // Update relayer stats
        _updateRelayerStats(deposit.relayer, relayerPayout, responseTime, tier);

        // Pay relayer instantly
        _safeTransferETH(deposit.relayer, relayerPayout);

        emit RelayRewardPaid(
            relayId,
            deposit.relayer,
            relayerPayout,
            tier,
            responseTime
        );

        // Refund surplus to requester if any (SLOW tier underpay)
        if (surplus > 0) {
            deposit.refunded = true;
            _safeTransferETH(deposit.requester, surplus);
            emit ExcessRefunded(relayId, deposit.requester, surplus);
        }
    }

    /// @notice Refund a deposit that was never completed
    /// @param relayId The relay to refund
    function refundDeposit(
        bytes32 relayId
    ) external nonReentrant onlyRole(RELAY_MANAGER_ROLE) {
        RelayDeposit storage deposit = deposits[relayId];
        if (deposit.requester == address(0)) revert DepositNotFound();
        if (deposit.completed) revert DepositAlreadyCompleted();
        if (deposit.refunded) revert DepositAlreadyRefunded();

        deposit.refunded = true;
        _safeTransferETH(deposit.requester, deposit.baseReward);

        emit ExcessRefunded(relayId, deposit.requester, deposit.baseReward);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated protocol fees
    /// @param to Recipient address
    function withdrawProtocolFees(
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = protocolFees;
        if (amount == 0) revert NoFeesToWithdraw();
        protocolFees = 0;
        _safeTransferETH(to, amount);
        emit ProtocolFeesWithdrawn(to, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the speed tier for a given response time
    /// @param responseTime Time in seconds from claim to completion
    /// @return tier The speed tier classification
    /// @return multiplier The reward multiplier in basis points
    function getSpeedTier(
        uint256 responseTime
    ) external pure returns (SpeedTier tier, uint256 multiplier) {
        return _getSpeedTier(responseTime);
    }

    /// @notice Calculate the expected reward for a given deposit and response time
    /// @param baseReward Deposit amount (funds max possible payout)
    /// @param responseTime Expected response time in seconds
    /// @return reward The calculated reward after tier and protocol fee
    function calculateReward(
        uint256 baseReward,
        uint256 responseTime
    ) external pure returns (uint256 reward) {
        (, uint256 multiplier) = _getSpeedTier(responseTime);
        uint256 tiered = (baseReward * multiplier) / MULTIPLIER_ULTRA_FAST;
        uint256 protocolCut = (tiered * PROTOCOL_FEE_BPS) / BPS;
        return tiered - protocolCut;
    }

    /// @notice Get a relayer's aggregate statistics
    function getRelayerStats(
        address relayer
    ) external view returns (RelayerStats memory) {
        return relayerStats[relayer];
    }

    /// @notice Get deposit details
    function getDeposit(
        bytes32 relayId
    ) external view returns (RelayDeposit memory) {
        return deposits[relayId];
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _getSpeedTier(
        uint256 responseTime
    ) internal pure returns (SpeedTier tier, uint256 multiplier) {
        if (responseTime < TIER_ULTRA_FAST) {
            return (SpeedTier.ULTRA_FAST, MULTIPLIER_ULTRA_FAST);
        } else if (responseTime < TIER_FAST) {
            return (SpeedTier.FAST, MULTIPLIER_FAST);
        } else if (responseTime < TIER_NORMAL) {
            return (SpeedTier.NORMAL, MULTIPLIER_NORMAL);
        } else {
            return (SpeedTier.SLOW, MULTIPLIER_SLOW);
        }
    }

    function _updateRelayerStats(
        address relayer,
        uint256 reward,
        uint256 responseTime,
        SpeedTier tier
    ) internal {
        RelayerStats storage stats = relayerStats[relayer];
        stats.totalRewards += reward;

        // Update weighted average response time
        if (stats.totalRelays > 0) {
            stats.avgResponseTime =
                (stats.avgResponseTime * stats.totalRelays + responseTime) /
                (stats.totalRelays + 1);
        } else {
            stats.avgResponseTime = responseTime;
        }

        stats.totalRelays++;

        if (tier == SpeedTier.ULTRA_FAST) {
            stats.ultraFastCount++;
        } else if (tier == SpeedTier.FAST) {
            stats.fastCount++;
        } else if (tier == SpeedTier.NORMAL) {
            stats.normalCount++;
        } else {
            stats.slowCount++;
        }
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    /// @notice Receive ETH (for direct deposits)
    receive() external payable {}
}
