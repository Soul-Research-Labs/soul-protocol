// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract ExecutionAgnosticStateCommitments is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function commitState(bytes32, bytes32) external {}
    function pause() external {}
    function unpause() external {}
    function deactivateBackend(bytes32) external {}
    function updateBackendTrust(bytes32, uint256) external {}
}
