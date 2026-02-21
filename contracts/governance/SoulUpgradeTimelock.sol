// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title SoulUpgradeTimelock
 * @author Soul Protocol
 * @notice Time-delayed upgrade controller for Soul protocol contracts
 * @dev Extends OpenZeppelin TimelockController with:
 *      - 48-72 hour upgrade delays
 *      - Multi-sig requirements
 *      - Emergency fast-track (reduced delay)
 *      - Upgrade pause period for user exit
 *
 * UPGRADE SECURITY ARCHITECTURE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                    UPGRADE TIMELOCK SYSTEM                             │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  ┌─────────────────┐     ┌─────────────────┐     ┌────────────────┐   │
 * │  │ Propose Upgrade │────►│ Timelock Queue  │────►│ Execute After  │   │
 * │  │ (Multi-sig)     │     │ (48-72 hours)   │     │ Delay          │   │
 * │  └─────────────────┘     └─────────────────┘     └────────────────┘   │
 * │          │                       │                       │            │
 * │          │               ┌───────▼───────┐               │            │
 * │          │               │ User Exit     │               │            │
 * │          │               │ Window        │               │            │
 * │          │               │ (24 hours)    │               │            │
 * │          │               └───────────────┘               │            │
 * │          │                                               │            │
 * │  ┌───────▼───────────────────────────────────────────────▼────────┐   │
 * │  │                    EMERGENCY PATH                              │   │
 * │  │  Guardian + 2/3 Multi-sig → 6 hour delay → Execute             │   │
 * │  └────────────────────────────────────────────────────────────────┘   │
 * │                                                                        │
 * └────────────────────────────────────────────────────────────────────────┘
 */
contract SoulUpgradeTimelock is TimelockController {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Standard upgrade delay (48 hours)
    uint256 public constant STANDARD_DELAY = 48 hours;

    /// @notice Extended upgrade delay for critical changes (72 hours)
    uint256 public constant EXTENDED_DELAY = 72 hours;

    /// @notice Emergency delay for critical fixes (6 hours)
    uint256 public constant EMERGENCY_DELAY = 6 hours;

    /// @notice User exit window before upgrade execution (24 hours)
    uint256 public constant EXIT_WINDOW = 24 hours;

    /// @notice Maximum delay allowed (7 days)
    uint256 public constant MAX_DELAY = 7 days;

    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADE_ROLE = keccak256("UPGRADE_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct UpgradeProposal {
        bytes32 operationId;
        address target;
        bytes data;
        uint256 proposedAt;
        uint256 scheduledAt;
        uint256 executableAt;
        bool isEmergency;
        bool isCritical;
        string description;
        uint256 exitWindowEnds;
    }

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of operation ID to upgrade details
    mapping(bytes32 => UpgradeProposal) public upgradeProposals;

    /// @notice List of all proposal IDs
    bytes32[] public proposalIds;

    /// @notice Mapping of contract to whether upgrades are frozen
    mapping(address => bool) public upgradeFrozen;

    /// @notice Whether emergency mode is active
    bool public emergencyMode;

    /// @notice Minimum required signatures for operations
    uint256 public minSignatures = 2;

    /// @notice Pending minimum signatures change (two-step pattern)
    uint256 public pendingMinSignatures;

    /// @notice Timestamp when pending min signatures change can be confirmed
    uint256 public minSignaturesEffectiveAt;

    /// @notice Collected signatures per operation
    mapping(bytes32 => mapping(address => bool)) public signatures;
    mapping(bytes32 => uint256) public signatureCount;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event UpgradeProposed(
        bytes32 indexed operationId,
        address indexed target,
        string description,
        uint256 executableAt,
        bool isEmergency
    );

    event UpgradeSigned(
        bytes32 indexed operationId,
        address indexed signer,
        uint256 signatureCount
    );

    event ExitWindowStarted(
        bytes32 indexed operationId,
        uint256 exitWindowEnds
    );

    event EmergencyModeEnabled(address indexed by);
    event EmergencyModeDisabled(address indexed by);
    event UpgradeFrozen(address indexed target, bool frozen);
    event MinSignaturesUpdated(uint256 oldMin, uint256 newMin);
    event MinSignaturesChangeProposed(
        uint256 currentMin,
        uint256 newMin,
        uint256 effectiveAt
    );
    event MinSignaturesChangeCancelled(uint256 cancelledValue);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error UpgradesFrozen(address target);
    error InsufficientSignatures(uint256 current, uint256 required);
    error AlreadySigned();
    error ExitWindowNotEnded(uint256 remaining);
    error InvalidDelay();
    error EmergencyOnly();
    error NotInEmergencyMode();
    error MinSignaturesTooLow();
    error NoPendingMinSignaturesChange();
    error MinSignaturesChangeNotReady(uint256 readyAt);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param minDelay Minimum delay for timelock operations
     * @param proposers Addresses that can propose upgrades
     * @param executors Addresses that can execute upgrades
     * @param admin Admin address
     */
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(UPGRADE_ROLE, admin);

        // Grant proposer role to all proposers
        for (uint256 i = 0; i < proposers.length; ) {
            _grantRole(UPGRADE_ROLE, proposers[i]);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                      UPGRADE PROPOSAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Propose a standard upgrade with 48-hour delay
     * @param target Target contract address
     * @param data Calldata for the upgrade
     * @param salt Unique salt for the operation
     * @param description Human-readable description
     * @return operationId The ID of the scheduled operation
     */
    function proposeUpgrade(
        address target,
        bytes calldata data,
        bytes32 salt,
        string calldata description
    ) external onlyRole(UPGRADE_ROLE) returns (bytes32 operationId) {
        if (upgradeFrozen[target]) revert UpgradesFrozen(target);

        operationId = hashOperation(target, 0, data, bytes32(0), salt);

        // Schedule with standard delay using public function
        schedule(target, 0, data, bytes32(0), salt, STANDARD_DELAY);

        upgradeProposals[operationId] = UpgradeProposal({
            operationId: operationId,
            target: target,
            data: data,
            proposedAt: block.timestamp,
            scheduledAt: block.timestamp,
            executableAt: block.timestamp + STANDARD_DELAY,
            isEmergency: false,
            isCritical: false,
            description: description,
            exitWindowEnds: block.timestamp + STANDARD_DELAY - EXIT_WINDOW
        });

        proposalIds.push(operationId);

        // First signature from proposer
        signatures[operationId][msg.sender] = true;
        signatureCount[operationId] = 1;

        emit UpgradeProposed(
            operationId,
            target,
            description,
            block.timestamp + STANDARD_DELAY,
            false
        );
        emit UpgradeSigned(operationId, msg.sender, 1);
    }

    /**
     * @notice Propose a critical upgrade with 72-hour delay
     * @param target Target contract address
     * @param data Calldata for the upgrade
     * @param salt Unique salt for the operation
     * @param description Human-readable description
     * @return operationId The ID of the scheduled operation
     */
    function proposeCriticalUpgrade(
        address target,
        bytes calldata data,
        bytes32 salt,
        string calldata description
    ) external onlyRole(UPGRADE_ROLE) returns (bytes32 operationId) {
        if (upgradeFrozen[target]) revert UpgradesFrozen(target);

        operationId = hashOperation(target, 0, data, bytes32(0), salt);

        // Schedule with extended delay using public function
        schedule(target, 0, data, bytes32(0), salt, EXTENDED_DELAY);

        upgradeProposals[operationId] = UpgradeProposal({
            operationId: operationId,
            target: target,
            data: data,
            proposedAt: block.timestamp,
            scheduledAt: block.timestamp,
            executableAt: block.timestamp + EXTENDED_DELAY,
            isEmergency: false,
            isCritical: true,
            description: description,
            exitWindowEnds: block.timestamp + EXTENDED_DELAY - EXIT_WINDOW
        });

        proposalIds.push(operationId);

        // First signature from proposer
        signatures[operationId][msg.sender] = true;
        signatureCount[operationId] = 1;

        emit UpgradeProposed(
            operationId,
            target,
            description,
            block.timestamp + EXTENDED_DELAY,
            false
        );
        emit UpgradeSigned(operationId, msg.sender, 1);
    }

    /**
     * @notice Propose an emergency upgrade with 6-hour delay
     * @dev Requires guardian role and emergency mode to be active
     * @param target Target contract address
     * @param data Calldata for the upgrade
     * @param salt Unique salt for the operation
     * @param description Human-readable description
     * @return operationId The ID of the scheduled operation
     */
    function proposeEmergencyUpgrade(
        address target,
        bytes calldata data,
        bytes32 salt,
        string calldata description
    ) external onlyRole(GUARDIAN_ROLE) returns (bytes32 operationId) {
        if (!emergencyMode) revert NotInEmergencyMode();
        if (upgradeFrozen[target]) revert UpgradesFrozen(target);

        operationId = hashOperation(target, 0, data, bytes32(0), salt);

        // Schedule with emergency delay using public function
        schedule(target, 0, data, bytes32(0), salt, EMERGENCY_DELAY);

        upgradeProposals[operationId] = UpgradeProposal({
            operationId: operationId,
            target: target,
            data: data,
            proposedAt: block.timestamp,
            scheduledAt: block.timestamp,
            executableAt: block.timestamp + EMERGENCY_DELAY,
            isEmergency: true,
            isCritical: false,
            description: description,
            exitWindowEnds: block.timestamp // No exit window for emergencies
        });

        proposalIds.push(operationId);

        // First signature from proposer
        signatures[operationId][msg.sender] = true;
        signatureCount[operationId] = 1;

        emit UpgradeProposed(
            operationId,
            target,
            description,
            block.timestamp + EMERGENCY_DELAY,
            true
        );
        emit UpgradeSigned(operationId, msg.sender, 1);
    }

    /**
     * @notice Sign an upgrade proposal
     * @param operationId The operation to sign
     */
    function signUpgrade(bytes32 operationId) external onlyRole(UPGRADE_ROLE) {
        if (signatures[operationId][msg.sender]) revert AlreadySigned();

        signatures[operationId][msg.sender] = true;
        signatureCount[operationId]++;

        emit UpgradeSigned(
            operationId,
            msg.sender,
            signatureCount[operationId]
        );
    }

    /**
     * @notice Execute an upgrade after timelock and signatures
     * @param target Target contract address
     * @param data Calldata for the upgrade
     * @param predecessor Required predecessor operation (0 if none)
     * @param salt Unique salt for the operation
     */
    function executeUpgrade(
        address target,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external onlyRole(UPGRADE_ROLE) {
        bytes32 operationId = hashOperation(target, 0, data, predecessor, salt);

        // Check signatures
        if (signatureCount[operationId] < minSignatures) {
            revert InsufficientSignatures(
                signatureCount[operationId],
                minSignatures
            );
        }

        // Check exit window for non-emergency upgrades
        UpgradeProposal storage proposal = upgradeProposals[operationId];
        if (
            !proposal.isEmergency && block.timestamp < proposal.exitWindowEnds
        ) {
            revert ExitWindowNotEnded(
                proposal.exitWindowEnds - block.timestamp
            );
        }

        // Execute through parent
        execute(target, 0, data, predecessor, salt);
    }

    /*//////////////////////////////////////////////////////////////
                      EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Enable emergency mode
     */
    function enableEmergencyMode() external onlyRole(GUARDIAN_ROLE) {
        emergencyMode = true;
        emit EmergencyModeEnabled(msg.sender);
    }

    /**
     * @notice Disable emergency mode
     */
    function disableEmergencyMode() external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyMode = false;
        emit EmergencyModeDisabled(msg.sender);
    }

    /**
     * @notice Freeze upgrades for a specific contract
     * @param target Contract to freeze
     * @param frozen Whether to freeze or unfreeze
     */
    function setUpgradeFrozen(
        address target,
        bool frozen
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        upgradeFrozen[target] = frozen;
        emit UpgradeFrozen(target, frozen);
    }

    /**
     * @notice Propose a change to minimum required signatures
     * @dev Increases take effect immediately (more secure). Reductions require
     *      a STANDARD_DELAY (48h) waiting period to prevent instant weakening
     *      of multi-sig protection.
     * @param newMin New minimum signatures required
     */
    function proposeMinSignatures(
        uint256 newMin
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newMin == 0) revert MinSignaturesTooLow();

        // Increases are safe — they only make things more secure
        if (newMin >= minSignatures) {
            uint256 oldMin = minSignatures;
            minSignatures = newMin;
            emit MinSignaturesUpdated(oldMin, newMin);
            return;
        }

        // Reductions require a delay to prevent instant weakening
        pendingMinSignatures = newMin;
        minSignaturesEffectiveAt = block.timestamp + STANDARD_DELAY;

        emit MinSignaturesChangeProposed(
            minSignatures,
            newMin,
            minSignaturesEffectiveAt
        );
    }

    /**
     * @notice Confirm a pending min signatures reduction after the delay
     */
    function confirmMinSignatures() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (pendingMinSignatures == 0) revert NoPendingMinSignaturesChange();
        if (block.timestamp < minSignaturesEffectiveAt) {
            revert MinSignaturesChangeNotReady(minSignaturesEffectiveAt);
        }

        uint256 oldMin = minSignatures;
        minSignatures = pendingMinSignatures;
        pendingMinSignatures = 0;
        minSignaturesEffectiveAt = 0;

        emit MinSignaturesUpdated(oldMin, minSignatures);
    }

    /**
     * @notice Cancel a pending min signatures change
     */
    function cancelMinSignaturesChange() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (pendingMinSignatures == 0) revert NoPendingMinSignaturesChange();

        uint256 cancelled = pendingMinSignatures;
        pendingMinSignatures = 0;
        minSignaturesEffectiveAt = 0;

        emit MinSignaturesChangeCancelled(cancelled);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get proposal count
     */
    function getProposalCount() external view returns (uint256) {
        return proposalIds.length;
    }

    /**
     * @notice Get proposal details
     */
    function getProposal(
        bytes32 operationId
    ) external view returns (UpgradeProposal memory) {
        return upgradeProposals[operationId];
    }

    /**
     * @notice Check if upgrade is ready to execute
     */
    function isUpgradeReady(bytes32 operationId) external view returns (bool) {
        UpgradeProposal storage proposal = upgradeProposals[operationId];

        return
            isOperationReady(operationId) &&
            signatureCount[operationId] >= minSignatures &&
            (proposal.isEmergency ||
                block.timestamp >= proposal.exitWindowEnds);
    }

    /**
     * @notice Get time until upgrade can be executed
     */
    function getTimeUntilExecutable(
        bytes32 operationId
    ) external view returns (uint256) {
        UpgradeProposal storage proposal = upgradeProposals[operationId];

        if (block.timestamp >= proposal.executableAt) {
            return 0;
        }
        return proposal.executableAt - block.timestamp;
    }
}
