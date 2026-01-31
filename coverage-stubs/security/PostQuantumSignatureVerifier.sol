// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract PostQuantumSignatureVerifier is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function verifySignature(bytes32, bytes calldata, bytes calldata) external view returns (bool) { return true; }
}
