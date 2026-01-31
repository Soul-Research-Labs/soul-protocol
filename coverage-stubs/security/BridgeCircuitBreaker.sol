// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract BridgeCircuitBreaker is AccessControl, Pausable {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function checkAndPause(bytes32) external {}
    function resetBreaker(bytes32) external {}
}
