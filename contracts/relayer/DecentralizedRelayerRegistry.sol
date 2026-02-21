// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title DecentralizedRelayerRegistry
 * @notice Permissionless registry for relayers with staking and slashing
 */
contract DecentralizedRelayerRegistry is AccessControl, ReentrancyGuard {
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    uint256 public constant MIN_STAKE = 10 ether;
    uint256 public constant UNBONDING_PERIOD = 7 days;

    struct RelayerInfo {
        uint256 stake;
        uint256 rewards;
        uint256 unlockTime; // 0 if active, > 0 if unbonding
        bool isRegistered;
    }

    mapping(address => RelayerInfo) public relayers;
    address[] public activeRelayers;

    event RelayerRegistered(address indexed relayer, uint256 stake);
    event StakeAdded(address indexed relayer, uint256 amount);
    event UnstakeInitiated(address indexed relayer, uint256 unlockTime);
    event StakeWithdrawn(address indexed relayer, uint256 amount);
    event RewardsClaimed(address indexed relayer, uint256 amount);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        address recipient
    );

    /// @notice Deploy the registry and grant admin roles
    /// @param _admin Address receiving DEFAULT_ADMIN_ROLE, GOVERNANCE_ROLE, and SLASHER_ROLE
    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(GOVERNANCE_ROLE, _admin);
        _grantRole(SLASHER_ROLE, _admin);
    }

    /**
     * @notice Register as a relayer with stake
     */
    function register() external payable nonReentrant {
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(!relayers[msg.sender].isRegistered, "Already registered");

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
     * @notice Add more stake
     */
    function depositStake() external payable nonReentrant {
        require(relayers[msg.sender].isRegistered, "Not registered");
        relayers[msg.sender].stake += msg.value;
        emit StakeAdded(msg.sender, msg.value);
    }

    /**
     * @notice Initiate unstaking
     */
    function initiateUnstake() external {
        require(relayers[msg.sender].isRegistered, "Not registered");
        require(relayers[msg.sender].unlockTime == 0, "Already unbonding");

        relayers[msg.sender].unlockTime = block.timestamp + UNBONDING_PERIOD;

        // Remove from active list?
        // For efficiency, we might just mark them inactive in a separate mapping or filter off-chain.
        // Here we keep them in struct but they are functionally inactive for selection if check unlockTime.

        emit UnstakeInitiated(msg.sender, relayers[msg.sender].unlockTime);
    }

    /**
     * @notice Withdraw stake after unbonding period
     */
    function withdrawStake() external nonReentrant {
        RelayerInfo storage info = relayers[msg.sender];
        require(info.unlockTime > 0, "Not unbonding");
        require(block.timestamp >= info.unlockTime, "Still locked");

        uint256 amount = info.stake;
        info.stake = 0;
        info.isRegistered = false;
        info.unlockTime = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit StakeWithdrawn(msg.sender, amount);
    }

    /**
     * @notice Slash a relayer for misconduct
     * @param _relayer Relayer to slash
     * @param _amount Amount to slash
     * @param _recipient Address to receive slashed funds (e.g., insurance fund or reporter)
     */
    function slash(
        address _relayer,
        uint256 _amount,
        address _recipient
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        RelayerInfo storage info = relayers[_relayer];
        require(info.stake >= _amount, "Insufficient stake");

        info.stake -= _amount;

        (bool success, ) = _recipient.call{value: _amount}("");
        require(success, "Transfer failed");

        emit RelayerSlashed(_relayer, _amount, _recipient);
    }

    /**
     * @notice Distribute rewards to a relayer
     */
    function addReward(address _relayer, uint256 _amount) external payable {
        // Anyone can fund rewards? Or just protocol?
        // Assuming protocol sends ETH to fund rewards.
        require(msg.value == _amount, "Value mismatch");
        require(relayers[_relayer].isRegistered, "Not registered");

        relayers[_relayer].rewards += _amount;
    }

    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external nonReentrant {
        uint256 amount = relayers[msg.sender].rewards;
        require(amount > 0, "No rewards");

        relayers[msg.sender].rewards = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit RewardsClaimed(msg.sender, amount);
    }

    // Helper to get active relayers count, list, etc.
}
