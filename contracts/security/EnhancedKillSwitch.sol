// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IEnhancedKillSwitch.sol";

/**
 * @title EnhancedKillSwitch
 * @notice Multi-level emergency response system with graduated shutdown capabilities
 * @dev Implements 5 emergency levels from WARNING to LOCKED with different restrictions
 * @author ZASEON Team
 * @custom:security-contact security@zaseon.network
 */
contract EnhancedKillSwitch is
    IEnhancedKillSwitch,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    // ============ Constants ============

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");

    /// @notice Time delays for escalation
    uint256 public constant LEVEL_1_COOLDOWN = 0; // Immediate
    uint256 public constant LEVEL_2_COOLDOWN = 1 hours; // 1 hour delay
    uint256 public constant LEVEL_3_COOLDOWN = 6 hours; // 6 hour delay
    uint256 public constant LEVEL_4_COOLDOWN = 24 hours; // 24 hour delay
    uint256 public constant LEVEL_5_COOLDOWN = 7 days; // 7 day delay (DAO vote)

    /// @notice Recovery delays
    uint256 public constant RECOVERY_DELAY = 48 hours;
    uint256 public constant FULL_RECOVERY_DELAY = 7 days;

    /// @notice Maximum guardian count
    uint256 public constant MAX_GUARDIANS = 15;

    /// @notice Required confirmations per level
    uint256 public constant LEVEL_3_CONFIRMATIONS = 2;
    uint256 public constant LEVEL_4_CONFIRMATIONS = 3;
    uint256 public constant LEVEL_5_CONFIRMATIONS = 5;

    // ============ Types ============

    // EmergencyLevel, ActionType, RecoveryRequest, EmergencyIncident, ProtocolState
    // are inherited from IEnhancedKillSwitch

    // ============ State Variables ============

    /// @notice Current emergency level
    EmergencyLevel public currentLevel;

    /// @notice Previous emergency level (for recovery)
    EmergencyLevel public previousLevel;

    /// @notice Timestamp when level was set
    uint256 public levelSetAt;

    /// @notice Pending level escalation
    EmergencyLevel public pendingLevel;

    /// @notice Pending level execution time
    uint256 public pendingLevelExecutableAt;

    /// @notice Confirmations for pending escalation
    mapping(EmergencyLevel => mapping(address => bool))
        public escalationConfirmations;

    /// @notice Confirmation count per level
    mapping(EmergencyLevel => uint256) public confirmationCount;

    /// @notice Recovery request
    RecoveryRequest public recoveryRequest;

    /// @notice Protected contracts
    mapping(address => bool) public protectedContracts;

    /// @notice Contract-specific overrides
    mapping(address => EmergencyLevel) public contractOverrides;

    /// @notice Action restrictions per level
    mapping(EmergencyLevel => mapping(ActionType => bool)) public actionAllowed;

    /// @notice Emergency incidents log
    EmergencyIncident[] public incidents;

    /// @notice Active guardians
    address[] public guardians;

    /// @notice Guardian status
    mapping(address => bool) public isGuardian;

    /// @notice Tracks which guardians have confirmed a recovery (keyed by requestedAt timestamp)
    mapping(uint256 => mapping(address => bool)) public recoveryConfirmed;

    // Structs (RecoveryRequest, EmergencyIncident, ProtocolState) inherited from IEnhancedKillSwitch

    // Events inherited from IEnhancedKillSwitch:
    // EmergencyLevelChanged, EscalationInitiated, EscalationConfirmed, EscalationExecuted,
    // EscalationCancelled, RecoveryInitiated, RecoveryExecuted, RecoveryCancelled,
    // GuardianAdded, GuardianRemoved, ContractProtected, ActionRestrictionUpdated

    // Errors inherited from IEnhancedKillSwitch:
    // InvalidLevel, LevelAlreadySet, CooldownNotPassed, InsufficientConfirmations,
    // AlreadyConfirmed, NoRecoveryPending, RecoveryNotExecutable, PermanentLockdown,
    // ActionNotAllowed, TooManyGuardians, NotGuardian, RecoveryDelayNotPassed,
    // EscalationPending, NoEscalationPending, AlreadyConfirmedRecovery

    // ============ Modifiers ============

    modifier onlyGuardian() {
        if (!isGuardian[msg.sender] && !hasRole(GUARDIAN_ROLE, msg.sender)) {
            revert NotGuardian();
        }
        _;
    }

    modifier notPermanent() {
        if (currentLevel == EmergencyLevel.PERMANENT) {
            revert PermanentLockdown();
        }
        _;
    }

    modifier actionAllowedModifier(ActionType action) {
        if (!_isActionAllowed(action)) {
            revert ActionNotAllowed();
        }
        _;
    }

    // ============ Constructor ============

    constructor(address _admin, address[] memory _guardians) {
        if (_admin == address(0)) revert InvalidLevel();
        if (_guardians.length > MAX_GUARDIANS) revert TooManyGuardians();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(RECOVERY_ROLE, _admin);

        // Add initial guardians
        for (uint256 i = 0; i < _guardians.length; ) {
            if (_guardians[i] != address(0)) {
                guardians.push(_guardians[i]);
                isGuardian[_guardians[i]] = true;
                _grantRole(GUARDIAN_ROLE, _guardians[i]);
                emit GuardianAdded(_guardians[i]);
            }
            unchecked {
                ++i;
            }
        }

        currentLevel = EmergencyLevel.NONE;

        // Set default action permissions
        _initializeActionPermissions();
    }

    // ============ External Functions ============

    /**
     * @notice Escalate emergency level (immediate for levels 1-2)
     * @param newLevel Target emergency level
     * @param reason Reason for escalation
     */
    function escalateEmergency(
        EmergencyLevel newLevel,
        string calldata reason
    ) external onlyGuardian notPermanent {
        if (newLevel <= currentLevel) revert InvalidLevel();
        if (pendingLevel != EmergencyLevel.NONE) revert EscalationPending();

        // Level 1-2: Immediate escalation
        if (newLevel <= EmergencyLevel.DEGRADED) {
            _setEmergencyLevel(newLevel, reason);
        }
        // Level 3-5: Requires timelock and confirmations
        else {
            _initiateEscalation(newLevel, reason);
        }
    }

    /**
     * @notice Confirm a pending escalation
     * @param level Level to confirm
     */
    function confirmEscalation(EmergencyLevel level) external onlyGuardian {
        if (pendingLevel != level) revert NoEscalationPending();
        if (escalationConfirmations[level][msg.sender])
            revert AlreadyConfirmed();

        escalationConfirmations[level][msg.sender] = true;
        confirmationCount[level]++;

        emit EscalationConfirmed(level, msg.sender, confirmationCount[level]);

        // Auto-execute if enough confirmations
        uint256 required = _getRequiredConfirmations(level);
        if (
            confirmationCount[level] >= required &&
            block.timestamp >= pendingLevelExecutableAt
        ) {
            _executeEscalation();
        }
    }

    /**
     * @notice Execute a pending escalation after cooldown
     */
    function executeEscalation() external onlyGuardian {
        if (pendingLevel == EmergencyLevel.NONE) revert NoEscalationPending();
        if (block.timestamp < pendingLevelExecutableAt)
            revert CooldownNotPassed();

        uint256 required = _getRequiredConfirmations(pendingLevel);
        if (confirmationCount[pendingLevel] < required) {
            revert InsufficientConfirmations();
        }

        _executeEscalation();
    }

    /**
     * @notice Cancel a pending escalation
     */
    function cancelEscalation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (pendingLevel == EmergencyLevel.NONE) revert NoEscalationPending();

        EmergencyLevel cancelled = pendingLevel;
        _clearPendingEscalation();

        emit EscalationCancelled(cancelled, msg.sender);
    }

    /**
     * @notice Initiate recovery to lower emergency level
     * @param targetLevel Target level to recover to
     */
    function initiateRecovery(
        EmergencyLevel targetLevel
    ) external onlyRole(RECOVERY_ROLE) notPermanent {
        if (targetLevel >= currentLevel) revert InvalidLevel();
        if (
            recoveryRequest.requestedAt > 0 &&
            !recoveryRequest.executed &&
            !recoveryRequest.cancelled
        ) {
            revert NoRecoveryPending();
        }

        uint256 delay = targetLevel == EmergencyLevel.NONE
            ? FULL_RECOVERY_DELAY
            : RECOVERY_DELAY;

        recoveryRequest = RecoveryRequest({
            targetLevel: targetLevel,
            initiator: msg.sender,
            requestedAt: block.timestamp,
            executableAt: block.timestamp + delay,
            confirmations: 1,
            executed: false,
            cancelled: false
        });

        emit RecoveryInitiated(
            targetLevel,
            msg.sender,
            block.timestamp + delay
        );
    }

    /**
     * @notice Confirm recovery request
     * @dev Each guardian can only confirm once per recovery request
     */
    function confirmRecovery() external onlyGuardian {
        if (
            recoveryRequest.requestedAt == 0 ||
            recoveryRequest.executed ||
            recoveryRequest.cancelled
        ) {
            revert NoRecoveryPending();
        }

        // Prevent duplicate confirmations from the same guardian
        if (recoveryConfirmed[recoveryRequest.requestedAt][msg.sender])
            revert AlreadyConfirmedRecovery();
        recoveryConfirmed[recoveryRequest.requestedAt][msg.sender] = true;

        recoveryRequest.confirmations++;
    }

    /**
     * @notice Execute recovery after delay
     */
    function executeRecovery() external onlyRole(RECOVERY_ROLE) {
        if (
            recoveryRequest.requestedAt == 0 ||
            recoveryRequest.executed ||
            recoveryRequest.cancelled
        ) {
            revert NoRecoveryPending();
        }
        if (block.timestamp < recoveryRequest.executableAt) {
            revert RecoveryDelayNotPassed();
        }

        // Require confirmations for full recovery
        if (
            recoveryRequest.targetLevel == EmergencyLevel.NONE &&
            recoveryRequest.confirmations < 3
        ) {
            revert InsufficientConfirmations();
        }

        recoveryRequest.executed = true;

        EmergencyLevel oldLevel = currentLevel;
        currentLevel = recoveryRequest.targetLevel;
        levelSetAt = block.timestamp;

        emit RecoveryExecuted(recoveryRequest.targetLevel, msg.sender);
        emit EmergencyLevelChanged(
            oldLevel,
            currentLevel,
            msg.sender,
            "Recovery executed"
        );
    }

    /**
     * @notice Cancel pending recovery
     */
    function cancelRecovery() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            recoveryRequest.requestedAt == 0 ||
            recoveryRequest.executed ||
            recoveryRequest.cancelled
        ) {
            revert NoRecoveryPending();
        }

        recoveryRequest.cancelled = true;
        emit RecoveryCancelled(msg.sender);
    }

    /**
     * @notice Check if an action is allowed at current level
     * @param action Action type to check
     * @return allowed True if action is allowed
     */
    function isActionAllowed(
        ActionType action
    ) external view returns (bool allowed) {
        return _isActionAllowed(action);
    }

    /**
     * @notice Get current protocol state
     * @return state Current operational state
     */
    function getProtocolState()
        external
        view
        returns (ProtocolState memory state)
    {
        return
            ProtocolState({
                depositsEnabled: _isActionAllowed(ActionType.DEPOSIT),
                withdrawalsEnabled: _isActionAllowed(ActionType.WITHDRAWAL),
                bridgingEnabled: _isActionAllowed(ActionType.BRIDGE),
                governanceEnabled: _isActionAllowed(ActionType.GOVERNANCE),
                upgradesEnabled: _isActionAllowed(ActionType.UPGRADE),
                emergencyWithdrawalsEnabled: _isActionAllowed(
                    ActionType.EMERGENCY_WITHDRAWAL
                )
            });
    }

    /**
     * @notice Get all incidents
     * @return All emergency incidents
     */
    function getIncidents() external view returns (EmergencyIncident[] memory) {
        return incidents;
    }

    /**
     * @notice Get guardian list
     * @return List of guardians
     */
    function getGuardians() external view returns (address[] memory) {
        return guardians;
    }

    // ============ Admin Functions ============

    /**
     * @notice Add a guardian
     * @param guardian Guardian address
     */
    function addGuardian(
        address guardian
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (guardians.length >= MAX_GUARDIANS) revert TooManyGuardians();
        if (isGuardian[guardian]) revert AlreadyConfirmed();

        guardians.push(guardian);
        isGuardian[guardian] = true;
        _grantRole(GUARDIAN_ROLE, guardian);

        emit GuardianAdded(guardian);
    }

    /**
     * @notice Remove a guardian
     * @param guardian Guardian address
     */
    function removeGuardian(
        address guardian
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!isGuardian[guardian]) revert NotGuardian();

        isGuardian[guardian] = false;
        _revokeRole(GUARDIAN_ROLE, guardian);

        // Remove from array
        for (uint256 i = 0; i < guardians.length; ) {
            if (guardians[i] == guardian) {
                guardians[i] = guardians[guardians.length - 1];
                guardians.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }

        emit GuardianRemoved(guardian);
    }

    /**
     * @notice Set contract protection status
     * @param contractAddr Contract address
     * @param status Protection status
     */
    function setProtectedContract(
        address contractAddr,
        bool status
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        protectedContracts[contractAddr] = status;
        emit ContractProtected(contractAddr, status);
    }

    /**
     * @notice Override emergency level for specific contract
     * @param contractAddr Contract address
     * @param level Override level
     */
    function setContractOverride(
        address contractAddr,
        EmergencyLevel level
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        contractOverrides[contractAddr] = level;
    }

    /**
     * @notice Update action restriction for a level
     * @param level Emergency level
     * @param action Action type
     * @param allowed Whether allowed
     */
    function setActionRestriction(
        EmergencyLevel level,
        ActionType action,
        bool allowed
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        actionAllowed[level][action] = allowed;
        emit ActionRestrictionUpdated(level, action, allowed);
    }

    // ============ Internal Functions ============

    function _setEmergencyLevel(
        EmergencyLevel newLevel,
        string memory reason
    ) internal {
        previousLevel = currentLevel;

        incidents.push(
            EmergencyIncident({
                id: incidents.length,
                fromLevel: currentLevel,
                toLevel: newLevel,
                initiator: msg.sender,
                timestamp: block.timestamp,
                reason: reason,
                evidenceHash: keccak256(bytes(reason))
            })
        );

        emit EmergencyLevelChanged(currentLevel, newLevel, msg.sender, reason);

        currentLevel = newLevel;
        levelSetAt = block.timestamp;

        // Apply pause if needed
        if (newLevel >= EmergencyLevel.HALTED && !paused()) {
            _pause();
        }
    }

    function _initiateEscalation(
        EmergencyLevel newLevel,
        string memory reason
    ) internal {
        uint256 cooldown = _getCooldown(newLevel);

        pendingLevel = newLevel;
        pendingLevelExecutableAt = block.timestamp + cooldown;

        // First confirmation from initiator
        escalationConfirmations[newLevel][msg.sender] = true;
        confirmationCount[newLevel] = 1;

        emit EscalationInitiated(
            newLevel,
            msg.sender,
            pendingLevelExecutableAt
        );

        // Log the reason
        incidents.push(
            EmergencyIncident({
                id: incidents.length,
                fromLevel: currentLevel,
                toLevel: newLevel,
                initiator: msg.sender,
                timestamp: block.timestamp,
                reason: reason,
                evidenceHash: keccak256(bytes(reason))
            })
        );
    }

    function _executeEscalation() internal {
        EmergencyLevel newLevel = pendingLevel;

        previousLevel = currentLevel;
        currentLevel = newLevel;
        levelSetAt = block.timestamp;

        emit EscalationExecuted(newLevel, msg.sender);
        emit EmergencyLevelChanged(
            previousLevel,
            newLevel,
            msg.sender,
            "Escalation executed"
        );

        _clearPendingEscalation();

        if (newLevel >= EmergencyLevel.HALTED && !paused()) {
            _pause();
        }
    }

    function _clearPendingEscalation() internal {
        // Clear confirmations
        for (uint256 i = 0; i < guardians.length; ) {
            escalationConfirmations[pendingLevel][guardians[i]] = false;
            unchecked {
                ++i;
            }
        }
        confirmationCount[pendingLevel] = 0;

        pendingLevel = EmergencyLevel.NONE;
        pendingLevelExecutableAt = 0;
    }

    function _getCooldown(
        EmergencyLevel level
    ) internal pure returns (uint256) {
        if (level == EmergencyLevel.HALTED) return LEVEL_3_COOLDOWN;
        if (level == EmergencyLevel.LOCKED) return LEVEL_4_COOLDOWN;
        if (level == EmergencyLevel.PERMANENT) return LEVEL_5_COOLDOWN;
        return LEVEL_1_COOLDOWN;
    }

    function _getRequiredConfirmations(
        EmergencyLevel level
    ) internal pure returns (uint256) {
        if (level == EmergencyLevel.HALTED) return LEVEL_3_CONFIRMATIONS;
        if (level == EmergencyLevel.LOCKED) return LEVEL_4_CONFIRMATIONS;
        if (level == EmergencyLevel.PERMANENT) return LEVEL_5_CONFIRMATIONS;
        return 1;
    }

    function _isActionAllowed(ActionType action) internal view returns (bool) {
        return actionAllowed[currentLevel][action];
    }

    function _initializeActionPermissions() internal {
        // NONE: Everything allowed
        actionAllowed[EmergencyLevel.NONE][ActionType.DEPOSIT] = true;
        actionAllowed[EmergencyLevel.NONE][ActionType.WITHDRAWAL] = true;
        actionAllowed[EmergencyLevel.NONE][ActionType.BRIDGE] = true;
        actionAllowed[EmergencyLevel.NONE][ActionType.GOVERNANCE] = true;
        actionAllowed[EmergencyLevel.NONE][ActionType.UPGRADE] = true;
        actionAllowed[EmergencyLevel.NONE][
            ActionType.EMERGENCY_WITHDRAWAL
        ] = true;

        // WARNING: Everything allowed (monitoring only)
        actionAllowed[EmergencyLevel.WARNING][ActionType.DEPOSIT] = true;
        actionAllowed[EmergencyLevel.WARNING][ActionType.WITHDRAWAL] = true;
        actionAllowed[EmergencyLevel.WARNING][ActionType.BRIDGE] = true;
        actionAllowed[EmergencyLevel.WARNING][ActionType.GOVERNANCE] = true;
        actionAllowed[EmergencyLevel.WARNING][ActionType.UPGRADE] = true;
        actionAllowed[EmergencyLevel.WARNING][
            ActionType.EMERGENCY_WITHDRAWAL
        ] = true;

        // DEGRADED: No new deposits
        actionAllowed[EmergencyLevel.DEGRADED][ActionType.DEPOSIT] = false;
        actionAllowed[EmergencyLevel.DEGRADED][ActionType.WITHDRAWAL] = true;
        actionAllowed[EmergencyLevel.DEGRADED][ActionType.BRIDGE] = false;
        actionAllowed[EmergencyLevel.DEGRADED][ActionType.GOVERNANCE] = true;
        actionAllowed[EmergencyLevel.DEGRADED][ActionType.UPGRADE] = false;
        actionAllowed[EmergencyLevel.DEGRADED][
            ActionType.EMERGENCY_WITHDRAWAL
        ] = true;

        // HALTED: Only withdrawals
        actionAllowed[EmergencyLevel.HALTED][ActionType.DEPOSIT] = false;
        actionAllowed[EmergencyLevel.HALTED][ActionType.WITHDRAWAL] = false;
        actionAllowed[EmergencyLevel.HALTED][ActionType.BRIDGE] = false;
        actionAllowed[EmergencyLevel.HALTED][ActionType.GOVERNANCE] = false;
        actionAllowed[EmergencyLevel.HALTED][ActionType.UPGRADE] = false;
        actionAllowed[EmergencyLevel.HALTED][
            ActionType.EMERGENCY_WITHDRAWAL
        ] = true;

        // LOCKED: Only emergency withdrawals with DAO approval
        actionAllowed[EmergencyLevel.LOCKED][ActionType.DEPOSIT] = false;
        actionAllowed[EmergencyLevel.LOCKED][ActionType.WITHDRAWAL] = false;
        actionAllowed[EmergencyLevel.LOCKED][ActionType.BRIDGE] = false;
        actionAllowed[EmergencyLevel.LOCKED][ActionType.GOVERNANCE] = true; // Need DAO to unlock
        actionAllowed[EmergencyLevel.LOCKED][ActionType.UPGRADE] = false;
        actionAllowed[EmergencyLevel.LOCKED][
            ActionType.EMERGENCY_WITHDRAWAL
        ] = true;

        // PERMANENT: Nothing allowed (catastrophic only)
        actionAllowed[EmergencyLevel.PERMANENT][ActionType.DEPOSIT] = false;
        actionAllowed[EmergencyLevel.PERMANENT][ActionType.WITHDRAWAL] = false;
        actionAllowed[EmergencyLevel.PERMANENT][ActionType.BRIDGE] = false;
        actionAllowed[EmergencyLevel.PERMANENT][ActionType.GOVERNANCE] = false;
        actionAllowed[EmergencyLevel.PERMANENT][ActionType.UPGRADE] = false;
        actionAllowed[EmergencyLevel.PERMANENT][
            ActionType.EMERGENCY_WITHDRAWAL
        ] = false;
    }
}
