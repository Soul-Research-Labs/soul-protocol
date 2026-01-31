// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract FHEOperations is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function addEncrypted(bytes calldata, bytes calldata) external pure returns (bytes memory) { return ""; }
    function subEncrypted(bytes calldata, bytes calldata) external pure returns (bytes memory) { return ""; }
}
