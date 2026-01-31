// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract ConfidentialStateContainerV3 is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function updateState(bytes32, bytes calldata) external {}
    function getState(bytes32) external view returns (bytes memory) { return ""; }
}
