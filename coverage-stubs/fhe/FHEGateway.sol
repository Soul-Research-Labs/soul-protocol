// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract FHEGateway is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function submitEncryptedCall(address, bytes calldata, bytes calldata) external returns (bytes32) { return bytes32(0); }
    function fulfillEncryptedCall(bytes32, bytes calldata) external {}
}
