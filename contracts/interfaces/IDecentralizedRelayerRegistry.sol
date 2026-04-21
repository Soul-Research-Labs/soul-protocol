// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IDecentralizedRelayerRegistry
 * @notice Interface for the DecentralizedRelayerRegistry staking and slashing contract
 * @dev Permissionless registry for relayers with staking, slashing, and reward distribution
 */
interface IDecentralizedRelayerRegistry {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct RelayerInfo {
        uint256 stake;
        uint256 rewards;
        uint256 unlockTime;
        bool isRegistered;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RelayerRegistered(address indexed relayer, uint256 stake);

    event StakeAdded(address indexed relayer, uint256 amount);

    event UnstakeInitiated(address indexed relayer, uint256 unlockTime);

    event StakeWithdrawn(address indexed relayer, uint256 amount);

    event RewardsClaimed(address indexed relayer, uint256 amount);

    event RewardAdded(
        address indexed relayer,
        address indexed funder,
        uint256 amount
    );

    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        address recipient
    );

    /// @notice Emitted when a refund escrows to pendingRefunds because the
    ///         synchronous push transfer failed (e.g., contract receiver
    ///         reverted on receive()).
    event RefundEscrowed(address indexed recipient, uint256 amount);

    /// @notice Emitted when a recipient successfully pulls their escrowed refund.
    event RefundClaimed(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InsufficientStake(uint256 provided, uint256 required);
    error AlreadyRegistered(address relayer);
    error NotRegistered(address relayer);
    error AlreadyUnbonding(address relayer, uint256 unlockTime);
    error NotUnbonding(address relayer);
    error StillLocked(uint256 unlockTime, uint256 currentTime);
    error InsufficientStakeForSlash(uint256 stake, uint256 slashAmount);
    error ValueMismatch(uint256 msgValue, uint256 amount);
    error NoRewards(address relayer);
    error TransferFailed(address recipient, uint256 amount);
    error NoPendingRefund();

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function SLASHER_ROLE() external view returns (bytes32);

    function GOVERNANCE_ROLE() external view returns (bytes32);

    function MIN_STAKE() external view returns (uint256);

    function UNBONDING_PERIOD() external view returns (uint256);

    function relayers(
        address relayer
    )
        external
        view
        returns (
            uint256 stake,
            uint256 rewards,
            uint256 unlockTime,
            bool isRegistered
        );

    function activeRelayers(uint256 index) external view returns (address);

    /*//////////////////////////////////////////////////////////////
                      REGISTRATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function register() external payable;

    function depositStake() external payable;

    /*//////////////////////////////////////////////////////////////
                     UNBONDING & WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    function initiateUnstake() external;

    function withdrawStake() external;

    /*//////////////////////////////////////////////////////////////
                           SLASHING
    //////////////////////////////////////////////////////////////*/

    function slash(
        address _relayer,
        uint256 _amount,
        address _recipient
    ) external;

    /*//////////////////////////////////////////////////////////////
                           REWARDS
    //////////////////////////////////////////////////////////////*/

    function addReward(address _relayer, uint256 _amount) external payable;

    function claimRewards() external;
}
