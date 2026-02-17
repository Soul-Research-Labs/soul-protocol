// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISoulUpgradeTimelock
 * @author Soul Protocol
 * @notice Interface for the Soul Protocol upgrade‐specific timelock controller.
 * @dev Mirrors the custom functionality exposed by SoulUpgradeTimelock on top of
 *      OpenZeppelin's TimelockController.  Contracts that interact with the
 *      timelock (e.g. SoulGovernor, deployment scripts) should depend on this
 *      interface rather than the concrete implementation.
 */
interface ISoulUpgradeTimelock {
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

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Standard upgrade delay (48 hours)
    function STANDARD_DELAY() external pure returns (uint256);

    /// @notice Extended delay for critical upgrades (72 hours)
    function EXTENDED_DELAY() external pure returns (uint256);

    /// @notice Emergency fast-track delay (6 hours)
    function EMERGENCY_DELAY() external pure returns (uint256);

    /// @notice User exit window before execution (24 hours)
    function EXIT_WINDOW() external pure returns (uint256);

    /// @notice Maximum permitted delay (7 days)
    function MAX_DELAY() external pure returns (uint256);

    /// @notice Role required to propose / execute upgrades
    function UPGRADE_ROLE() external pure returns (bytes32);

    /// @notice Guardian role for emergency operations
    function GUARDIAN_ROLE() external pure returns (bytes32);

    /*//////////////////////////////////////////////////////////////
                            STATE READERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Whether emergency mode is currently active
    function emergencyMode() external view returns (bool);

    /// @notice Minimum multi-sig signatures required
    function minSignatures() external view returns (uint256);

    /// @notice Whether upgrades are frozen for a given target
    function upgradeFrozen(address target) external view returns (bool);

    /// @notice Returns a proposal by its operation ID
    function getProposal(
        bytes32 operationId
    ) external view returns (UpgradeProposal memory);

    /// @notice Returns the total number of proposals
    function getProposalCount() external view returns (uint256);

    /// @notice Checks whether an upgrade is ready for execution
    function isUpgradeReady(bytes32 operationId) external view returns (bool);

    /// @notice Time remaining until an upgrade becomes executable
    function getTimeUntilExecutable(
        bytes32 operationId
    ) external view returns (uint256);

    /// @notice Signature count for a given operation
    function signatureCount(
        bytes32 operationId
    ) external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                          UPGRADE LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Proposes a standard upgrade (48h delay)
     * @param target  Contract to upgrade
     * @param data    Upgrade calldata
     * @param salt    Unique salt
     * @param description Human‐readable description
     * @return operationId The timelock operation hash
     */
    function proposeUpgrade(
        address target,
        bytes calldata data,
        bytes32 salt,
        string calldata description
    ) external returns (bytes32 operationId);

    /**
     * @notice Proposes a critical upgrade (72h delay)
     * @param target  Contract to upgrade
     * @param data    Upgrade calldata
     * @param salt    Unique salt
     * @param description Human‐readable description
     * @return operationId The timelock operation hash
     */
    function proposeCriticalUpgrade(
        address target,
        bytes calldata data,
        bytes32 salt,
        string calldata description
    ) external returns (bytes32 operationId);

    /**
     * @notice Proposes an emergency upgrade (6h delay, guardian only)
     * @param target  Contract to upgrade
     * @param data    Upgrade calldata
     * @param salt    Unique salt
     * @param description Human‐readable description
     * @return operationId The timelock operation hash
     */
    function proposeEmergencyUpgrade(
        address target,
        bytes calldata data,
        bytes32 salt,
        string calldata description
    ) external returns (bytes32 operationId);

    /**
     * @notice Adds a multi-sig signature to an upgrade proposal
     * @param operationId The operation to sign
     */
    function signUpgrade(bytes32 operationId) external;

    /**
     * @notice Executes a ready upgrade through the timelock
     * @param target      Target contract
     * @param data        Upgrade calldata
     * @param predecessor Predecessor operation (0 for none)
     * @param salt        Salt used when proposing
     */
    function executeUpgrade(
        address target,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external;

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables emergency mode (guardian only)
    function enableEmergencyMode() external;

    /// @notice Disables emergency mode (admin only)
    function disableEmergencyMode() external;

    /*//////////////////////////////////////////////////////////////
                          ADMIN CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Freezes or unfreezes upgrades for a target contract
    function setUpgradeFrozen(address target, bool frozen) external;

    /// @notice Updates the minimum required signatures
    function setMinSignatures(uint256 newMin) external;
}
