// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// STUB for coverage only
contract RelayerStaking is AccessControl, ReentrancyGuard {
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    IERC20 public stakingToken;
    uint256 public minStake;
    uint256 public constant UNBONDING_PERIOD = 7 days;
    uint256 public slashingPercentage;
    uint256 public totalStaked;
    uint256 public rewardPool;
    uint256 public rewardPerShare;
    uint256 public constant PRECISION = 1e18;
    uint256 public constant MIN_STAKE_DURATION = 1 days;

    struct Relayer {
        uint256 stakedAmount;
        uint256 pendingUnstake;
        uint256 unstakeRequestTime;
        uint256 rewardDebt;
        uint256 successfulRelays;
        uint256 failedRelays;
        bool isActive;
        string metadata;
    }

    mapping(address => Relayer) public relayers;
    address[] public activeRelayers;
    mapping(address => uint256) public relayerIndex;
    mapping(address => uint256) public stakingTimestamp;

    constructor(address _stakingToken, uint256 _minStake, address admin) {
        stakingToken = IERC20(_stakingToken);
        minStake = _minStake;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function stake(uint256) external {}
    function requestUnstake(uint256) external {}
    function completeUnstake() external {}
    function slash(address, string calldata) external {}
    function recordSuccessfulRelay(address) external {}
    function claimRewards() external {}
    function addRewards(uint256) external {}
    function pendingRewards(address) external view returns (uint256) { return 0; }
    function getActiveRelayers() external view returns (address[] memory) { return activeRelayers; }
    function getActiveRelayerCount() external view returns (uint256) { return activeRelayers.length; }
    function isActiveRelayer(address) external view returns (bool) { return true; }
    function setMinStake(uint256) external {}
    function setSlashingPercentage(uint256) external {}
    function updateMetadata(string calldata) external {}
}
