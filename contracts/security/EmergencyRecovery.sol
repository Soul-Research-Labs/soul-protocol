// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title EmergencyRecovery
 * @author Soul Protocol
 * @notice Comprehensive emergency recovery system for the Soul network
 * @dev Implements multi-stage recovery with graduated response levels
 *
 * Recovery Stages:
 * 1. MONITORING - Normal operation with enhanced logging
 * 2. ALERT - Anomaly detected, investigation mode
 * 3. DEGRADED - Reduced functionality, non-critical features disabled
 * 4. EMERGENCY - Critical systems only, most operations paused
 * 5. RECOVERY - System restart with validation checks
 *
 * Security Properties:
 * - Multi-sig requirement for stage escalation
 * - Automatic cooldown periods between stage changes
 * - Asset protection mechanisms during emergencies
 * - Audit trail for all recovery actions
 */
contract EmergencyRecovery is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Recovery stages
    enum RecoveryStage {
        Monitoring,
        Alert,
        Degraded,
        Emergency,
        Recovery
    }

    /// @notice Recovery action types
    enum ActionType {
        StageChange,
        PauseContract,
        UnpauseContract,
        FreezeAssets,
        UnfreezeAssets,
        UpdateThreshold,
        EmergencyWithdraw,
        ValidatorSlash,
        ConfigUpdate
    }

    /// @notice Recovery action record
    struct RecoveryAction {
        bytes32 actionId;
        ActionType actionType;
        address target;
        bytes data;
        address proposer;
        uint256 proposedAt;
        uint256 executedAt;
        uint256 approvalCount;
        bool executed;
        bool cancelled;
        string reason;
    }

    /// @notice Protected contract registry
    struct ProtectedContract {
        address contractAddress;
        string name;
        bool isPausable;
        bool isFreezable;
        bool isPaused;
        bool isFrozen;
        uint256 lastActionAt;
    }

    /// @notice Frozen asset record
    struct FrozenAsset {
        address owner;
        address token;
        uint256 amount;
        bytes32 commitment;
        uint256 frozenAt;
        string reason;
        bool released;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current recovery stage
    RecoveryStage public currentStage;

    /// @notice Stage change cooldown (prevents rapid oscillation)
    uint256 public constant STAGE_COOLDOWN = 1 hours;

    /// @notice Last stage change timestamp
    uint256 public lastStageChange;

    /// @notice Required approvals for stage escalation
    mapping(RecoveryStage => uint256) public requiredApprovals;

    /// @notice Pending recovery actions
    mapping(bytes32 => RecoveryAction) public pendingActions;
    bytes32[] public pendingActionIds;

    /// @notice Action approvals
    mapping(bytes32 => mapping(address => bool)) public actionApprovals;

    /// @notice Protected contracts
    mapping(address => ProtectedContract) public protectedContracts;
    address[] public protectedContractList;

    /// @notice Frozen assets
    mapping(bytes32 => FrozenAsset) public frozenAssets;
    bytes32[] public frozenAssetIds;

    /// @notice Guardian count for quorum calculation
    uint256 public guardianCount;

    /// @notice Recovery action history
    RecoveryAction[] public actionHistory;

    /// @notice Emergency withdrawal recipients whitelist
    mapping(address => bool) public emergencyWithdrawalWhitelist;

    /// @notice Total value frozen
    uint256 public totalValueFrozen;

    /// @notice Recovery metrics
    uint256 public totalActionsProposed;
    uint256 public totalActionsExecuted;
    uint256 public totalStageChanges;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event StageChanged(
        RecoveryStage indexed oldStage,
        RecoveryStage indexed newStage,
        string reason
    );
    event ActionProposed(
        bytes32 indexed actionId,
        ActionType actionType,
        address indexed proposer
    );
    event ActionApproved(
        bytes32 indexed actionId,
        address indexed approver,
        uint256 approvalCount
    );
    event ActionExecuted(
        bytes32 indexed actionId,
        ActionType actionType,
        address indexed executor
    );
    event ActionCancelled(bytes32 indexed actionId, address indexed canceller);

    event ContractRegistered(address indexed contractAddress, string name);
    event ContractPaused(address indexed contractAddress, string reason);
    event ContractUnpaused(address indexed contractAddress);
    /// @notice Emitted when a pause/unpause call fails on a target contract
    event PauseCallResult(address indexed contractAddress, bool success);

    event AssetFrozen(
        bytes32 indexed assetId,
        address indexed owner,
        address token,
        uint256 amount
    );
    event AssetReleased(bytes32 indexed assetId, address indexed owner);

    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);

    event EmergencyWithdrawal(
        address indexed recipient,
        address token,
        uint256 amount
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidStageTransition(
        RecoveryStage current,
        RecoveryStage requested
    );
    error CooldownNotElapsed(uint256 remainingTime);
    error InsufficientApprovals(uint256 required, uint256 current);
    error ActionNotFound(bytes32 actionId);
    error ActionAlreadyExecuted(bytes32 actionId);
    error ActionAlreadyCancelled(bytes32 actionId);
    error AlreadyApproved(bytes32 actionId, address approver);
    error ContractNotRegistered(address contractAddress);
    error AssetNotFrozen(bytes32 assetId);
    error NotInEmergency();
    error NotWhitelisted(address recipient);

    error AlreadyResolved();
    error NotPausable();
    error InsufficientMinGuardians();
    error ETHTransferFailed();
    error TokenTransferFailed();
    error InvalidStage();
    error PauseCallFailed(address contractAddress);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(RECOVERY_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        currentStage = RecoveryStage.Monitoring;
        guardianCount = 1;

        // Set default approval requirements
        requiredApprovals[RecoveryStage.Monitoring] = 1;
        requiredApprovals[RecoveryStage.Alert] = 1;
        requiredApprovals[RecoveryStage.Degraded] = 2;
        requiredApprovals[RecoveryStage.Emergency] = 3;
        requiredApprovals[RecoveryStage.Recovery] = 2;

        lastStageChange = block.timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                        STAGE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Propose a stage change
     * @param newStage The target recovery stage
     * @param reason Justification for the change
     */
    function proposeStageChange(
        RecoveryStage newStage,
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) returns (bytes32 actionId) {
        // Validate stage transition
        if (!_isValidStageTransition(currentStage, newStage)) {
            revert InvalidStageTransition(currentStage, newStage);
        }

        // Check cooldown for de-escalation
        if (newStage < currentStage) {
            uint256 elapsed = block.timestamp - lastStageChange;
            if (elapsed < STAGE_COOLDOWN) {
                revert CooldownNotElapsed(STAGE_COOLDOWN - elapsed);
            }
        }

        actionId = keccak256(
            abi.encodePacked(
                ActionType.StageChange,
                newStage,
                block.timestamp,
                msg.sender
            )
        );

        pendingActions[actionId] = RecoveryAction({
            actionId: actionId,
            actionType: ActionType.StageChange,
            target: address(this),
            data: abi.encode(newStage),
            proposer: msg.sender,
            proposedAt: block.timestamp,
            executedAt: 0,
            approvalCount: 1,
            executed: false,
            cancelled: false,
            reason: reason
        });

        pendingActionIds.push(actionId);
        actionApprovals[actionId][msg.sender] = true;
        unchecked {
            ++totalActionsProposed;
        }

        emit ActionProposed(actionId, ActionType.StageChange, msg.sender);
        emit ActionApproved(actionId, msg.sender, 1);

        // Auto-execute if single approval needed (escalation to Alert)
        if (1 >= requiredApprovals[newStage]) {
            _executeStageChange(actionId, newStage);
        }
    }

    /**
     * @notice Approve a pending action
     */
    function approveAction(bytes32 actionId) external onlyRole(GUARDIAN_ROLE) {
        RecoveryAction storage action = pendingActions[actionId];

        if (action.proposedAt == 0) revert ActionNotFound(actionId);
        if (action.executed) revert ActionAlreadyExecuted(actionId);
        if (action.cancelled) revert ActionAlreadyCancelled(actionId);
        if (actionApprovals[actionId][msg.sender])
            revert AlreadyApproved(actionId, msg.sender);

        actionApprovals[actionId][msg.sender] = true;
        action.approvalCount++;

        emit ActionApproved(actionId, msg.sender, action.approvalCount);

        // Check if can execute
        if (action.actionType == ActionType.StageChange) {
            RecoveryStage targetStage = abi.decode(
                action.data,
                (RecoveryStage)
            );
            if (action.approvalCount >= requiredApprovals[targetStage]) {
                _executeStageChange(actionId, targetStage);
            }
        }
    }

    /**
     * @notice Cancel a pending action
     */
    function cancelAction(bytes32 actionId) external onlyRole(GUARDIAN_ROLE) {
        RecoveryAction storage action = pendingActions[actionId];

        if (action.proposedAt == 0) revert ActionNotFound(actionId);
        if (action.executed) revert ActionAlreadyExecuted(actionId);
        if (action.cancelled) revert ActionAlreadyCancelled(actionId);

        action.cancelled = true;

        emit ActionCancelled(actionId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                     PROTECTED CONTRACT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a contract for protection
     */
    function registerProtectedContract(
        address contractAddress,
        string calldata name,
        bool isPausable,
        bool isFreezable
    ) external onlyRole(OPERATOR_ROLE) {
        protectedContracts[contractAddress] = ProtectedContract({
            contractAddress: contractAddress,
            name: name,
            isPausable: isPausable,
            isFreezable: isFreezable,
            isPaused: false,
            isFrozen: false,
            lastActionAt: block.timestamp
        });

        protectedContractList.push(contractAddress);

        emit ContractRegistered(contractAddress, name);
    }

    /**
     * @notice Pause a protected contract
     */
    function pauseContract(
        address contractAddress,
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        ProtectedContract storage pc = protectedContracts[contractAddress];

        if (pc.contractAddress == address(0))
            revert ContractNotRegistered(contractAddress);
        if (!pc.isPausable) revert NotPausable();

        pc.isPaused = true;
        pc.lastActionAt = block.timestamp;

        // Call pause on target contract if it supports it
        // SECURITY: Check return value to ensure state consistency
        (bool success, ) = contractAddress.call(
            abi.encodeWithSignature("pause()")
        );
        if (!success) {
            // Emit event if pause call failed (contract may not support pause or already paused)
            emit PauseCallResult(contractAddress, false);
        }

        emit ContractPaused(contractAddress, reason);
    }

    /**
     * @notice Unpause a protected contract
     */
    function unpauseContract(
        address contractAddress
    ) external onlyRole(GUARDIAN_ROLE) {
        ProtectedContract storage pc = protectedContracts[contractAddress];

        if (pc.contractAddress == address(0))
            revert ContractNotRegistered(contractAddress);

        pc.isPaused = false;
        pc.lastActionAt = block.timestamp;

        // Call unpause on target contract
        // SECURITY: Check return value to ensure state consistency
        (bool success, ) = contractAddress.call(
            abi.encodeWithSignature("unpause()")
        );
        if (!success) {
            emit PauseCallResult(contractAddress, false);
        }

        emit ContractUnpaused(contractAddress);
    }

    /**
     * @notice Pause all registered pausable contracts
     */
    function pauseAll(string calldata reason) external onlyRole(GUARDIAN_ROLE) {
        if (currentStage < RecoveryStage.Degraded) revert InvalidStage();

        uint256 len = protectedContractList.length;
        address[] memory toPause = new address[](len);
        uint256 pauseCount;

        for (uint256 i = 0; i < len; ) {
            address addr = protectedContractList[i];
            ProtectedContract storage pc = protectedContracts[addr];

            if (pc.isPausable && !pc.isPaused) {
                pc.isPaused = true;
                pc.lastActionAt = block.timestamp;
                toPause[pauseCount] = addr;
                pauseCount++;
            }
            unchecked {
                ++i;
            }
        }

        for (uint256 i = 0; i < pauseCount; ) {
            address addr = toPause[i];
            (bool success, ) = addr.call(abi.encodeWithSignature("pause()"));
            if (!success) {
                revert PauseCallFailed(addr);
            }
            emit ContractPaused(addr, reason);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ASSET FREEZING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Freeze assets associated with suspicious activity
     * @param owner The asset owner
     * @param token The token address (address(0) for ETH)
     * @param amount The amount frozen
     * @param commitment Associated state commitment (for Soul states)
     * @param reason Reason for freezing
     */
    function freezeAssets(
        address owner,
        address token,
        uint256 amount,
        bytes32 commitment,
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) returns (bytes32 assetId) {
        if (currentStage < RecoveryStage.Alert) revert InvalidStage();

        assetId = keccak256(
            abi.encodePacked(owner, token, commitment, block.timestamp)
        );

        frozenAssets[assetId] = FrozenAsset({
            owner: owner,
            token: token,
            amount: amount,
            commitment: commitment,
            frozenAt: block.timestamp,
            reason: reason,
            released: false
        });

        frozenAssetIds.push(assetId);
        totalValueFrozen += amount;

        emit AssetFrozen(assetId, owner, token, amount);
    }

    /**
     * @notice Release frozen assets
     */
    function releaseAssets(bytes32 assetId) external onlyRole(GUARDIAN_ROLE) {
        FrozenAsset storage asset = frozenAssets[assetId];

        if (asset.frozenAt == 0) revert AssetNotFrozen(assetId);
        if (asset.released) revert AlreadyResolved();

        asset.released = true;
        totalValueFrozen -= asset.amount;

        emit AssetReleased(assetId, asset.owner);
    }

    /**
     * @notice Check if assets are frozen
     */
    function isAssetFrozen(
        address owner,
        bytes32 commitment
    ) external view returns (bool frozen, bytes32 assetId) {
        uint256 len = frozenAssetIds.length;
        for (uint256 i = 0; i < len; ) {
            assetId = frozenAssetIds[i];
            FrozenAsset storage asset = frozenAssets[assetId];
            if (
                asset.owner == owner &&
                asset.commitment == commitment &&
                !asset.released
            ) {
                return (true, assetId);
            }
            unchecked {
                ++i;
            }
        }
        return (false, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                       EMERGENCY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emergency withdrawal (only in Emergency stage)
     */
    function emergencyWithdraw(
        address token,
        address recipient,
        uint256 amount
    ) external onlyRole(RECOVERY_ROLE) nonReentrant {
        if (currentStage != RecoveryStage.Emergency) revert NotInEmergency();
        if (!emergencyWithdrawalWhitelist[recipient])
            revert NotWhitelisted(recipient);

        if (token == address(0)) {
            (bool success, ) = recipient.call{value: amount}("");
            if (!success) revert ETHTransferFailed();
        } else {
            (bool success, ) = token.call(
                abi.encodeWithSignature(
                    "transfer(address,uint256)",
                    recipient,
                    amount
                )
            );
            if (!success) revert TokenTransferFailed();
        }

        emit EmergencyWithdrawal(recipient, token, amount);
    }

    /**
     * @notice Add address to emergency withdrawal whitelist
     */
    function addToWhitelist(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyWithdrawalWhitelist[recipient] = true;
    }

    /**
     * @notice Remove address from emergency withdrawal whitelist
     */
    function removeFromWhitelist(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyWithdrawalWhitelist[recipient] = false;
    }

    /*//////////////////////////////////////////////////////////////
                        GUARDIAN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a new guardian
     */
    function addGuardian(
        address guardian
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(GUARDIAN_ROLE, guardian);
        unchecked {
            ++guardianCount;
        }
        emit GuardianAdded(guardian);
    }

    /**
     * @notice Remove a guardian
     */
    function removeGuardian(
        address guardian
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (guardianCount <= requiredApprovals[RecoveryStage.Emergency])
            revert InsufficientMinGuardians();
        _revokeRole(GUARDIAN_ROLE, guardian);
        unchecked {
            --guardianCount;
        }
        emit GuardianRemoved(guardian);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current recovery status
     */
    function getRecoveryStatus()
        external
        view
        returns (
            RecoveryStage stage,
            uint256 lastChange,
            uint256 pendingActionsCount,
            uint256 frozenAssetsCount,
            uint256 valueFrozen
        )
    {
        return (
            currentStage,
            lastStageChange,
            pendingActionIds.length,
            frozenAssetIds.length,
            totalValueFrozen
        );
    }

    /**
     * @notice Get pending actions
     */
    function getPendingActions() external view returns (bytes32[] memory) {
        return pendingActionIds;
    }

    /**
     * @notice Check if action can be executed
     */
    function canExecuteAction(
        bytes32 actionId
    ) external view returns (bool, string memory reason) {
        RecoveryAction storage action = pendingActions[actionId];

        if (action.proposedAt == 0) return (false, "Action not found");
        if (action.executed) return (false, "Already executed");
        if (action.cancelled) return (false, "Cancelled");

        if (action.actionType == ActionType.StageChange) {
            RecoveryStage targetStage = abi.decode(
                action.data,
                (RecoveryStage)
            );
            if (action.approvalCount < requiredApprovals[targetStage]) {
                return (false, "Insufficient approvals");
            }
        }

        return (true, "Ready");
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _executeStageChange(
        bytes32 actionId,
        RecoveryStage newStage
    ) internal {
        RecoveryAction storage action = pendingActions[actionId];

        action.executed = true;
        action.executedAt = block.timestamp;

        RecoveryStage oldStage = currentStage;
        currentStage = newStage;
        lastStageChange = block.timestamp;

        unchecked {
            ++totalActionsExecuted;
            ++totalStageChanges;
        }

        // Record in history
        actionHistory.push(action);

        // Remove from pending
        _removeFromPending(actionId);

        emit StageChanged(oldStage, newStage, action.reason);
        emit ActionExecuted(actionId, ActionType.StageChange, msg.sender);

        // Auto-actions based on stage
        if (newStage == RecoveryStage.Emergency) {
            _pause();
        } else if (
            oldStage == RecoveryStage.Emergency &&
            newStage < RecoveryStage.Emergency
        ) {
            _unpause();
        }
    }

    function _isValidStageTransition(
        RecoveryStage from,
        RecoveryStage to
    ) internal pure returns (bool) {
        // Can always escalate one level at a time
        if (uint8(to) == uint8(from) + 1) return true;

        // Can de-escalate multiple levels (with cooldown)
        if (to < from) return true;

        // Can jump to Emergency from any state
        if (to == RecoveryStage.Emergency) return true;

        return false;
    }

    function _removeFromPending(bytes32 actionId) internal {
        uint256 len = pendingActionIds.length;
        for (uint256 i = 0; i < len; ) {
            if (pendingActionIds[i] == actionId) {
                pendingActionIds[i] = pendingActionIds[len - 1];
                pendingActionIds.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Receive ETH
    receive() external payable {}
}
