// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract CrossChainMessageRelay is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function relayMessage(uint256, bytes32, bytes calldata) external payable {}
}
