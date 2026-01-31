// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract CryptographicAttestation is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function verifyAttestation(bytes32, bytes calldata) external view returns (bool) { return true; }
}
