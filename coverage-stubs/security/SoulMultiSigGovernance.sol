// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract SoulMultiSigGovernance is AccessControl {
    constructor(address[] memory, uint256) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function submitTransaction(address, uint256, bytes calldata) external returns (uint256) { return 0; }
    function confirmTransaction(uint256) external {}
    function executeTransaction(uint256) external payable {}
}
