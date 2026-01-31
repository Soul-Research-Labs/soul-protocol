// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract SharedSequencer is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    enum SequencerStatus { UNREGISTERED, PENDING, ACTIVE, STANDBY, JAILED, EXITING, EXITED }
    enum ChainType { ARBITRUM, OPTIMISM, BASE, ZKSYNC, STARKNET, SCROLL, LINEA, POLYGON_ZKEVM }

    struct Sequencer {
        address operator;
        address signer;
        uint256 stake;
        uint256 registeredAt;
        uint256 lastActiveSlot;
        SequencerStatus status;
        uint256 blocksProduced;
        uint256 blocksMissed;
        uint256 slashingPoints;
        ChainType[] supportedChains;
        uint256 exitInitiatedAt;
        uint256 unstakeAmount;
    }

    mapping(address => Sequencer) public sequencers;
    uint256 public totalSequencers;
    uint256 public totalStaked;
    uint256 public currentSlot;

    constructor(uint256, uint256, uint256, uint256) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function registerSequencer(address, ChainType[] calldata) external payable {}
    function addStake() external payable {}
    function activateSequencer(address) external {}
    function initiateExit() external {}
    function completeExit() external {}
    function advanceSlot() external {}
    function submitBatch(ChainType[] calldata, bytes32[] calldata, bytes32) external returns (bytes32) { return bytes32(0); }
    function finalizeBatch(bytes32, bytes32) external {}
    function triggerRotation() external {}
    function slashSequencer(address, string calldata) external {}
    
    function getCurrentSlot() public view returns (uint256) { return currentSlot; }
    function isEligibleForActiveSet(address) external view returns (bool) { return true; }
    function getActiveSequencers() external view returns (address[] memory) { return new address[](0); }
    function getSequencer(address) external view returns (Sequencer memory) { 
        return sequencers[msg.sender]; // Return a stubbed sequencer
    }

    function getSequencerCount() external view returns (uint256) { return totalSequencers; }
}
