// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract HomomorphicBalanceVerifier is AccessControl {
    struct BalanceProof {
        bytes32 proofId;
        bytes32 oldBalanceCommitment;
        bytes32 newBalanceCommitment;
        bytes32 transferCommitment;
        bytes proof;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function verifyBalanceProof(bytes32, bytes32, bytes32, bytes calldata) external returns (bool) { return true; }
    function verifyRangeProof(bytes32, bytes calldata) external view returns (bool) { return true; }
}
