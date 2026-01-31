// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/TimelockController.sol";

// STUB for coverage only
contract SoulUpgradeTimelock is TimelockController {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADE_ROLE = keccak256("UPGRADE_ROLE");
    uint256 public constant STANDARD_DELAY = 48 hours;
    uint256 public constant EXTENDED_DELAY = 72 hours;
    uint256 public constant EMERGENCY_DELAY = 6 hours;
    uint256 public constant EXIT_WINDOW = 24 hours;

    struct UpgradeProposal { bytes32 operationId; address target; bytes data; uint256 proposedAt; uint256 scheduledAt; uint256 executableAt; bool isEmergency; bool isCritical; string description; uint256 exitWindowEnds; }
    
    mapping(bytes32 => UpgradeProposal) public upgradeProposals;
    mapping(address => bool) public upgradeFrozen;
    bool public emergencyMode;
    uint256 public minSignatures = 2;
    mapping(bytes32 => mapping(address => bool)) public signatures;
    mapping(bytes32 => uint256) public signatureCount;

    event UpgradeProposed(bytes32 indexed operationId, address indexed target, string description, uint256 executableAt, bool isEmergency);
    event UpgradeSigned(bytes32 indexed operationId, address indexed signer, uint256 signatureCount);
    event EmergencyModeEnabled(address indexed by);
    event EmergencyModeDisabled(address indexed by);

    constructor(uint256 minDelay, address[] memory proposers, address[] memory executors, address admin) 
        TimelockController(minDelay, proposers, executors, admin) 
    {
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(UPGRADE_ROLE, admin);
    }

    function proposeUpgrade(address t, bytes calldata d, bytes32 s, string calldata desc) external returns (bytes32 id) {
        id = hashOperation(t, 0, d, bytes32(0), s);
        upgradeProposals[id] = UpgradeProposal(id, t, d, block.timestamp, block.timestamp, block.timestamp + STANDARD_DELAY, false, false, desc, block.timestamp);
        emit UpgradeProposed(id, t, desc, block.timestamp + STANDARD_DELAY, false);
        return id;
    }
    function proposeCriticalUpgrade(address, bytes calldata, bytes32, string calldata) external returns (bytes32) { return bytes32(0); }
    function proposeEmergencyUpgrade(address, bytes calldata, bytes32, string calldata) external returns (bytes32) { return bytes32(0); }
    function signUpgrade(bytes32 id) external { signatures[id][msg.sender] = true; signatureCount[id]++; emit UpgradeSigned(id, msg.sender, signatureCount[id]); }
    function executeUpgrade(address, bytes calldata, bytes32, bytes32) external {}
    function enableEmergencyMode() external { emergencyMode = true; emit EmergencyModeEnabled(msg.sender); }
    function disableEmergencyMode() external { emergencyMode = false; emit EmergencyModeDisabled(msg.sender); }
    function setUpgradeFrozen(address, bool) external {}
    function setMinSignatures(uint256) external {}
    function getProposal(bytes32 id) external view returns (UpgradeProposal memory) { return upgradeProposals[id]; }
    function isUpgradeReady(bytes32) external pure returns (bool) { return true; }
    function getTimeUntilExecutable(bytes32) external pure returns (uint256) { return 0; }
}
