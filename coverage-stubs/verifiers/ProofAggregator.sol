// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract ProofAggregator is AccessControl {
    struct AggregatedProof {
        bytes32 aggregationId;
        bytes32[] proofIds;
        bytes aggregatedProof;
        bool verified;
    }

    mapping(bytes32 => AggregatedProof) public aggregations;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function aggregateProofs(bytes32[] calldata, bytes calldata) external returns (bytes32) { return bytes32(0); }
    function verifyAggregatedProof(bytes32) external returns (bool) { return true; }
}
