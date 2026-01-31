// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract AztecBridgeAdapter is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    bool public paused;
    function pause() external { paused = true; }
    function unpause() external { paused = false; }

    function bridgeToAztec(address, uint256, bytes32) external payable {}
}
