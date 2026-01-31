// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract EncryptedVoting is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function castEncryptedVote(uint256, bytes calldata) external {}
    function tallyVotes(uint256) external view returns (bytes memory) { return ""; }
}
