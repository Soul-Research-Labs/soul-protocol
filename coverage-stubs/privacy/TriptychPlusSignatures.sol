// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract TriptychPlusSignatures is AccessControl {
    struct TriptychPlusSignature {
        bytes32[] commitments;
        bytes32 challenge;
        bytes32[] responses;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function verifySignature(bytes32, TriptychPlusSignature calldata) external view returns (bool) { return true; }
    function verifyBatch(bytes32[] calldata, TriptychPlusSignature[] calldata) external view returns (bool) { return true; }
}
