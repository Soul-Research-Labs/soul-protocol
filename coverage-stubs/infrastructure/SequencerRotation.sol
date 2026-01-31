// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract SequencerRotation is AccessControl, Pausable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function rotateSequencer() external {}
    function getCurrentSequencer() external view returns (address) { return address(0); }
    function getNextSequencer() external view returns (address) { return address(0); }
}
